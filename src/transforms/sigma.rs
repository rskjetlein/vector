use std::{
    collections::{BTreeSet, HashMap},
    convert::TryFrom,
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use vector_lib::{
    configurable::configurable_component,
    event::{Event, LogEvent, Value},
    lookup::{OwnedTargetPath, owned_value_path},
};

use crate::{
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform},
};

const DEFAULT_CONDITION_KEY: &str = "condition";
static MATCHES_PATH: LazyLock<OwnedTargetPath> =
    LazyLock::new(|| OwnedTargetPath::event(owned_value_path!("sigma", "matches")));

/// Configuration for the `sigma` transform.
#[configurable_component(transform("sigma", "Evaluate incoming log events against Sigma rules.",))]
#[derive(Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SigmaConfig {
    /// Paths to files that contain Sigma rules in YAML format. Multiple documents may be present
    /// in each file and all of them will be loaded.
    #[serde(default)]
    pub rules_files: Vec<PathBuf>,
}

impl GenerateConfig for SigmaConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(r#"rules_files = ["/etc/vector/sigma/windows_process_creation.yml"]"#)
            .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "sigma")]
impl TransformConfig for SigmaConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        let mut compiled_rules = Vec::new();

        for path in &self.rules_files {
            compiled_rules.extend(load_rules_from_path(path)?);
        }

        if compiled_rules.is_empty() {
            return Err(crate::Error::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sigma transform requires at least one rule",
            )));
        }

        Ok(Transform::function(Sigma::new(compiled_rules)))
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn outputs(
        &self,
        _enrichment_tables: vector_lib::enrichment::TableRegistry,
        input_definitions: &[(OutputId, schema::Definition)],
        _: vector_lib::config::LogNamespace,
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(
            DataType::Log,
            vector_lib::config::clone_input_definitions(input_definitions),
        )]
    }

    fn enable_concurrency(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
pub struct Sigma {
    rules: Vec<CompiledRule>,
}

impl Sigma {
    fn new(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    fn evaluate<'a>(&'a self, log: &'a LogEvent) -> Vec<&'a CompiledRule> {
        self.rules.iter().filter(|rule| rule.matches(log)).collect()
    }
}

impl FunctionTransform for Sigma {
    fn transform(&mut self, output: &mut OutputBuffer, event: Event) {
        match event {
            Event::Log(mut log) => {
                let matches = self.evaluate(&log);

                if !matches.is_empty() {
                    let values = matches
                        .iter()
                        .map(|rule| Value::from(rule.display_name.clone()))
                        .collect::<Vec<_>>();
                    log.insert(&*MATCHES_PATH, Value::Array(values));
                } else {
                    log.remove(&*MATCHES_PATH);
                }

                output.push(Event::Log(log));
            }
            other => {
                output.push(other);
            }
        }
    }
}

fn load_rules_from_path(path: &Path) -> crate::Result<Vec<CompiledRule>> {
    let contents = fs::read_to_string(path).map_err(crate::Error::from)?;
    load_rules_from_str(&contents, path)
}

fn load_rules_from_str(contents: &str, path: &Path) -> crate::Result<Vec<CompiledRule>> {
    let mut rules = Vec::new();

    for (index, document) in serde_yaml::Deserializer::from_str(contents).enumerate() {
        let raw = RawSigmaRule::deserialize(document).map_err(crate::Error::from)?;
        rules.push(CompiledRule::try_from_raw(raw, path, index)?);
    }

    Ok(rules)
}

#[derive(Debug, Deserialize)]
struct RawSigmaRule {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    id: Option<String>,
    detection: YamlValue,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    display_name: String,
    selections: Vec<Selection>,
    condition: ConditionNode,
}

impl CompiledRule {
    fn matches(&self, log: &LogEvent) -> bool {
        let mut evaluator = SelectionEvaluator::new(log, &self.selections);
        self.condition.evaluate(&mut evaluator)
    }

    fn try_from_raw(raw: RawSigmaRule, path: &Path, ordinal: usize) -> crate::Result<Self> {
        let ParsedDetection {
            selections,
            condition,
        } = parse_detection(raw.detection, path)?;

        if selections.is_empty() {
            return Err(invalid_data(
                path,
                "Sigma rule must define at least one selection",
            ));
        }

        let display_name = raw
            .title
            .or(raw.id)
            .unwrap_or_else(|| format!("{}#{}", path.display(), ordinal))
            .trim()
            .to_owned();

        Ok(Self {
            display_name,
            selections,
            condition,
        })
    }
}

#[derive(Clone, Debug)]
struct Selection {
    name: String,
    predicates: Vec<SelectionPredicate>,
}

impl Selection {
    fn matches(&self, log: &LogEvent) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(log))
    }
}

#[derive(Clone, Debug)]
struct SelectionPredicate {
    path: String,
    matcher: FieldMatcher,
}

impl SelectionPredicate {
    fn matches(&self, log: &LogEvent) -> bool {
        match log.parse_path_and_get_value(&self.path) {
            Ok(Some(value)) => self.matcher.matches(&value),
            _ => false,
        }
    }
}

#[derive(Debug)]
struct ParsedDetection {
    selections: Vec<Selection>,
    condition: ConditionNode,
}

fn parse_detection(detection: YamlValue, path: &Path) -> crate::Result<ParsedDetection> {
    let mapping = detection
        .as_mapping()
        .ok_or_else(|| invalid_data(path, "Sigma rule detection section must be a mapping"))?;

    let mut selections = Vec::new();
    let mut selection_names = Vec::new();
    let mut condition = None;

    for (key, value) in mapping {
        let key = key
            .as_str()
            .ok_or_else(|| invalid_data(path, "Detection keys must be strings"))?;

        if key.eq_ignore_ascii_case(DEFAULT_CONDITION_KEY) {
            condition = Some(
                value
                    .as_str()
                    .ok_or_else(|| invalid_data(path, "Detection condition must be a string"))?
                    .to_owned(),
            );
            continue;
        }

        if key.eq_ignore_ascii_case("timeframe") {
            if !value.is_string() {
                return Err(invalid_data(
                    path,
                    "Detection timeframe must be provided as a string value",
                ));
            }
            continue;
        }

        let selection = parse_selection(key, value, path)?;
        selection_names.push(selection.name.clone());
        selections.push(selection);
    }

    if selections.is_empty() {
        return Err(invalid_data(
            path,
            "Detection section must include at least one selection block",
        ));
    }

    let name_map: HashMap<String, usize> = selection_names
        .iter()
        .enumerate()
        .map(|(index, name)| (name.clone(), index))
        .collect();

    let condition = if let Some(condition) = condition {
        parse_condition(&condition, &selection_names, &name_map, path)?
    } else {
        let members: Vec<usize> = (0..selection_names.len()).collect();
        ConditionNode::Threshold { min: 1, members }
    };

    Ok(ParsedDetection {
        selections,
        condition,
    })
}

fn parse_selection(name: &str, value: &YamlValue, path: &Path) -> crate::Result<Selection> {
    let selection_map = value.as_mapping().ok_or_else(|| {
        invalid_data(
            path,
            format!("Selection '{name}' entries must be mappings of field to value"),
        )
    })?;

    if selection_map.is_empty() {
        return Err(invalid_data(
            path,
            format!("Selection '{name}' must define at least one predicate"),
        ));
    }

    let mut predicates = Vec::new();

    for (field_key, field_value) in selection_map {
        let field_name = field_key
            .as_str()
            .ok_or_else(|| invalid_data(path, "Selection field keys must be strings"))?;

        let expected_values = match field_value {
            YamlValue::Sequence(seq) => {
                if seq.is_empty() {
                    return Err(invalid_data(
                        path,
                        format!(
                            "Selection field '{field_name}' may not provide an empty list of expected values"
                        ),
                    ));
                }
                seq.iter()
                    .map(|item| yaml_scalar_to_value(path, field_name, item))
                    .collect::<crate::Result<Vec<_>>>()?
            }
            other => vec![yaml_scalar_to_value(path, field_name, other)?],
        };

        let predicate = build_predicate(field_name, expected_values, path)?;
        predicates.push(predicate);
    }

    Ok(Selection {
        name: name.to_owned(),
        predicates,
    })
}

#[derive(Clone, Debug)]
struct SelectionEvaluator<'log> {
    log: &'log LogEvent,
    selections: &'log [Selection],
    cache: Vec<Option<bool>>,
}

impl<'log> SelectionEvaluator<'log> {
    fn new(log: &'log LogEvent, selections: &'log [Selection]) -> Self {
        Self {
            log,
            selections,
            cache: vec![None; selections.len()],
        }
    }

    fn evaluate_selection(&mut self, index: usize) -> bool {
        if let Some(result) = self.cache[index] {
            return result;
        }

        let result = self.selections[index].matches(self.log);
        self.cache[index] = Some(result);
        result
    }
}

#[derive(Clone, Debug)]
enum ConditionNode {
    Selection(usize),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    Not(Box<ConditionNode>),
    Threshold { min: usize, members: Vec<usize> },
}

impl ConditionNode {
    fn evaluate(&self, evaluator: &mut SelectionEvaluator<'_>) -> bool {
        match self {
            ConditionNode::Selection(index) => evaluator.evaluate_selection(*index),
            ConditionNode::And(children) => children.iter().all(|child| child.evaluate(evaluator)),
            ConditionNode::Or(children) => children.iter().any(|child| child.evaluate(evaluator)),
            ConditionNode::Not(child) => !child.evaluate(evaluator),
            ConditionNode::Threshold { min, members } => {
                let mut matched = 0usize;
                for &index in members {
                    if evaluator.evaluate_selection(index) {
                        matched += 1;
                        if matched >= *min {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}

fn parse_condition(
    condition: &str,
    selection_names: &[String],
    name_map: &HashMap<String, usize>,
    path: &Path,
) -> crate::Result<ConditionNode> {
    let tokens = ConditionLexer::new(condition, path).collect::<crate::Result<Vec<_>>>()?;
    let mut parser = ConditionParser::new(tokens, selection_names, name_map, path);
    parser.parse_expression()
}

#[derive(Clone, Debug)]
enum Token {
    Identifier(String),
    Number(usize),
    And,
    Or,
    Not,
    Of,
    All,
    Any,
    LParen,
    RParen,
    Comma,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Identifier,
    Number,
    And,
    Or,
    Not,
    Of,
    All,
    Any,
    LParen,
    RParen,
    Comma,
}

impl From<&Token> for TokenKind {
    fn from(token: &Token) -> Self {
        match token {
            Token::Identifier(_) => TokenKind::Identifier,
            Token::Number(_) => TokenKind::Number,
            Token::And => TokenKind::And,
            Token::Or => TokenKind::Or,
            Token::Not => TokenKind::Not,
            Token::Of => TokenKind::Of,
            Token::All => TokenKind::All,
            Token::Any => TokenKind::Any,
            Token::LParen => TokenKind::LParen,
            Token::RParen => TokenKind::RParen,
            Token::Comma => TokenKind::Comma,
        }
    }
}

struct ConditionLexer<'a> {
    chars: std::str::Chars<'a>,
    buffer: Option<char>,
    path: &'a Path,
}

impl<'a> ConditionLexer<'a> {
    fn new(condition: &'a str, path: &'a Path) -> Self {
        Self {
            chars: condition.chars(),
            buffer: None,
            path,
        }
    }

    fn next_char(&mut self) -> Option<char> {
        if let Some(ch) = self.buffer.take() {
            Some(ch)
        } else {
            self.chars.next()
        }
    }

    fn push_back(&mut self, ch: char) {
        self.buffer = Some(ch);
    }
}

impl<'a> Iterator for ConditionLexer<'a> {
    type Item = crate::Result<Token>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(ch) = self.next_char() {
            if ch.is_whitespace() {
                continue;
            }

            return Some(match ch {
                '(' => Ok(Token::LParen),
                ')' => Ok(Token::RParen),
                ',' => Ok(Token::Comma),
                '0'..='9' => {
                    let mut text = ch.to_string();
                    while let Some(next) = self.next_char() {
                        if next.is_ascii_digit() {
                            text.push(next);
                        } else {
                            self.push_back(next);
                            break;
                        }
                    }
                    match text.parse::<usize>() {
                        Ok(number) => Ok(Token::Number(number)),
                        Err(err) => Err(invalid_data(
                            self.path,
                            format!("Failed to parse number '{text}' in Sigma condition: {err}"),
                        )),
                    }
                }
                _ => {
                    let mut ident = ch.to_string();
                    while let Some(next) = self.next_char() {
                        if next.is_whitespace() || matches!(next, '(' | ')' | ',') {
                            self.push_back(next);
                            break;
                        }
                        ident.push(next);
                    }

                    let lower = ident.to_ascii_lowercase();
                    match lower.as_str() {
                        "and" => Ok(Token::And),
                        "or" => Ok(Token::Or),
                        "not" => Ok(Token::Not),
                        "of" => Ok(Token::Of),
                        "all" => Ok(Token::All),
                        "any" => Ok(Token::Any),
                        _ => Ok(Token::Identifier(ident)),
                    }
                }
            });
        }

        None
    }
}

struct ConditionParser<'a> {
    tokens: Vec<Token>,
    position: usize,
    selection_names: &'a [String],
    name_map: &'a HashMap<String, usize>,
    path: &'a Path,
}

impl<'a> ConditionParser<'a> {
    fn new(
        tokens: Vec<Token>,
        selection_names: &'a [String],
        name_map: &'a HashMap<String, usize>,
        path: &'a Path,
    ) -> Self {
        Self {
            tokens,
            position: 0,
            selection_names,
            name_map,
            path,
        }
    }

    fn parse_expression(&mut self) -> crate::Result<ConditionNode> {
        let node = self.parse_or()?;
        if self.position != self.tokens.len() {
            return Err(invalid_data(
                self.path,
                "Condition contains unexpected trailing tokens",
            ));
        }
        Ok(node)
    }

    fn parse_or(&mut self) -> crate::Result<ConditionNode> {
        let mut clauses = vec![self.parse_and()?];

        while self.match_token(TokenKind::Or) {
            clauses.push(self.parse_and()?);
        }

        if clauses.len() == 1 {
            Ok(clauses.remove(0))
        } else {
            Ok(ConditionNode::Or(clauses))
        }
    }

    fn parse_and(&mut self) -> crate::Result<ConditionNode> {
        let mut clauses = vec![self.parse_not()?];

        while self.match_token(TokenKind::And) {
            clauses.push(self.parse_not()?);
        }

        if clauses.len() == 1 {
            Ok(clauses.remove(0))
        } else {
            Ok(ConditionNode::And(clauses))
        }
    }

    fn parse_not(&mut self) -> crate::Result<ConditionNode> {
        if self.match_token(TokenKind::Not) {
            let node = self.parse_not()?;
            Ok(ConditionNode::Not(Box::new(node)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> crate::Result<ConditionNode> {
        match self.peek_token() {
            Some(TokenKind::LParen) => {
                self.consume_token(TokenKind::LParen)?;
                let expr = self.parse_or()?;
                self.consume_token(TokenKind::RParen)?;
                Ok(expr)
            }
            _ if self.lookahead_is_quantity() => self.parse_threshold(),
            Some(TokenKind::Identifier) => {
                let ident = self.consume_identifier()?;
                if self.match_token(TokenKind::Of) {
                    let quantity = self.quantity_from_identifier(&ident)?;
                    self.parse_threshold_with_quantity(quantity)
                } else {
                    let indices = self.resolve_identifier(&ident)?;
                    if indices.len() != 1 {
                        return Err(invalid_data(
                            self.path,
                            format!(
                                "Condition reference '{ident}' resolved to multiple selections"
                            ),
                        ));
                    }
                    Ok(ConditionNode::Selection(indices[0]))
                }
            }
            other => Err(invalid_data(
                self.path,
                format!("Unexpected token in condition: {:?}", other),
            )),
        }
    }

    fn lookahead_is_quantity(&self) -> bool {
        match self.tokens.get(self.position) {
            Some(Token::Number(_)) | Some(Token::All) | Some(Token::Any) => true,
            Some(Token::Identifier(ident)) => {
                matches!(self.tokens.get(self.position + 1), Some(Token::Of)) && {
                    let lower = ident.to_ascii_lowercase();
                    lower == "all" || lower == "any" || lower.chars().all(|ch| ch.is_ascii_digit())
                }
            }
            _ => false,
        }
    }

    fn parse_threshold(&mut self) -> crate::Result<ConditionNode> {
        let quantity = match self.next_token() {
            Some(Token::Number(value)) => Quantity::Exactly(value),
            Some(Token::All) => Quantity::All,
            Some(Token::Any) => Quantity::Any,
            Some(Token::Identifier(ident)) => self.quantity_from_identifier(&ident)?,
            other => {
                return Err(invalid_data(
                    self.path,
                    format!("Expected quantity in condition but found {:?}", other),
                ));
            }
        };

        self.consume_token(TokenKind::Of)?;
        self.parse_threshold_with_quantity(quantity)
    }

    fn quantity_from_identifier(&self, ident: &str) -> crate::Result<Quantity> {
        let lower = ident.to_ascii_lowercase();
        if lower == "all" {
            Ok(Quantity::All)
        } else if lower == "any" {
            Ok(Quantity::Any)
        } else {
            lower.parse::<usize>().map(Quantity::Exactly).map_err(|_| {
                invalid_data(
                    self.path,
                    format!("Unable to parse quantity '{ident}' in condition"),
                )
            })
        }
    }

    fn parse_threshold_with_quantity(
        &mut self,
        quantity: Quantity,
    ) -> crate::Result<ConditionNode> {
        let targets = self.parse_target_list()?;
        let members = self.resolve_targets(targets)?;

        if members.is_empty() {
            return Err(invalid_data(
                self.path,
                "Condition quantifier resolved to an empty set of selections",
            ));
        }

        let min = match quantity {
            Quantity::Any => 1,
            Quantity::All => members.len(),
            Quantity::Exactly(value) => value,
        };

        Ok(ConditionNode::Threshold { min, members })
    }

    fn parse_target_list(&mut self) -> crate::Result<TargetList> {
        if self.match_token(TokenKind::LParen) {
            let mut identifiers = Vec::new();
            loop {
                identifiers.push(self.consume_identifier()?);
                if self.match_token(TokenKind::Comma) {
                    continue;
                }
                self.consume_token(TokenKind::RParen)?;
                break;
            }
            return Ok(TargetList::Identifiers(identifiers));
        }

        let ident = self.consume_identifier()?;
        if ident.eq_ignore_ascii_case("them") {
            Ok(TargetList::Them)
        } else {
            let mut identifiers = vec![ident];
            while self.match_token(TokenKind::Comma) {
                identifiers.push(self.consume_identifier()?);
            }
            Ok(TargetList::Identifiers(identifiers))
        }
    }

    fn resolve_targets(&self, targets: TargetList) -> crate::Result<Vec<usize>> {
        let mut indices = BTreeSet::new();

        match targets {
            TargetList::Them => {
                indices.extend(0..self.selection_names.len());
            }
            TargetList::Identifiers(names) => {
                for name in names {
                    for index in self.resolve_identifier(&name)? {
                        indices.insert(index);
                    }
                }
            }
        }

        Ok(indices.into_iter().collect())
    }

    fn resolve_identifier(&self, ident: &str) -> crate::Result<Vec<usize>> {
        if ident.contains('*') {
            let regex = compile_wildcard_pattern(ident, self.path)?;
            let matches: Vec<usize> = self
                .selection_names
                .iter()
                .enumerate()
                .filter_map(|(index, name)| {
                    if regex.is_match(name) {
                        Some(index)
                    } else {
                        None
                    }
                })
                .collect();
            if matches.is_empty() {
                Err(invalid_data(
                    self.path,
                    format!("Condition wildcard '{ident}' did not match any selections"),
                ))
            } else {
                Ok(matches)
            }
        } else {
            let index = *self.name_map.get(ident).ok_or_else(|| {
                invalid_data(
                    self.path,
                    format!("Condition references unknown selection '{ident}'"),
                )
            })?;
            Ok(vec![index])
        }
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.position >= self.tokens.len() {
            None
        } else {
            let token = self.tokens[self.position].clone();
            self.position += 1;
            Some(token)
        }
    }

    fn peek_token(&self) -> Option<TokenKind> {
        self.tokens.get(self.position).map(TokenKind::from)
    }

    fn match_token(&mut self, kind: TokenKind) -> bool {
        if self.peek_token() == Some(kind) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn consume_token(&mut self, kind: TokenKind) -> crate::Result<()> {
        if self.match_token(kind) {
            Ok(())
        } else {
            Err(invalid_data(
                self.path,
                format!("Expected {:?} in condition", kind),
            ))
        }
    }

    fn consume_identifier(&mut self) -> crate::Result<String> {
        match self.next_token() {
            Some(Token::Identifier(ident)) => Ok(ident),
            other => Err(invalid_data(
                self.path,
                format!("Expected identifier in condition but found {:?}", other),
            )),
        }
    }
}

#[derive(Clone, Debug)]
enum TargetList {
    Them,
    Identifiers(Vec<String>),
}

#[derive(Clone, Copy, Debug)]
enum Quantity {
    Any,
    All,
    Exactly(usize),
}

fn compile_wildcard_pattern(pattern: &str, path: &Path) -> crate::Result<Regex> {
    let mut regex = String::from("^");
    let mut parts = pattern.split('*').peekable();
    while let Some(part) = parts.next() {
        regex.push_str(&regex::escape(part));
        if parts.peek().is_some() {
            regex.push_str(".*");
        }
    }
    regex.push('$');

    Regex::new(&regex).map_err(|err| {
        invalid_data(
            path,
            format!("Invalid wildcard pattern '{pattern}' in condition: {err}"),
        )
    })
}

#[derive(Clone, Debug)]
struct FieldMatcher {
    comparator: Comparator,
    aggregator: Aggregator,
}

impl FieldMatcher {
    fn matches(&self, value: &Value) -> bool {
        match value {
            Value::Array(array) => array.iter().any(|item| self.matches_scalar(item)),
            other => self.matches_scalar(other),
        }
    }

    fn matches_scalar(&self, value: &Value) -> bool {
        match self.aggregator {
            Aggregator::Any => self.comparator.matches_any(value),
            Aggregator::All => self.comparator.matches_all(value),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Aggregator {
    Any,
    All,
}

#[derive(Clone, Debug)]
enum Comparator {
    Equals(EqualityComparator),
    Contains(StringComparator),
    StartsWith(StringComparator),
    EndsWith(StringComparator),
    Regex(RegexComparator),
    Cidr(CidrComparator),
    Numeric(NumericComparator),
}

impl Comparator {
    fn matches_any(&self, value: &Value) -> bool {
        match self {
            Comparator::Equals(comparator) => comparator.matches_any(value),
            Comparator::Contains(comparator) => {
                comparator.matches_any(value, |haystack, needle| haystack.contains(needle))
            }
            Comparator::StartsWith(comparator) => {
                comparator.matches_any(value, |haystack, needle| haystack.starts_with(needle))
            }
            Comparator::EndsWith(comparator) => {
                comparator.matches_any(value, |haystack, needle| haystack.ends_with(needle))
            }
            Comparator::Regex(comparator) => comparator.matches_any(value),
            Comparator::Cidr(comparator) => comparator.matches_any(value),
            Comparator::Numeric(comparator) => comparator.matches_any(value),
        }
    }

    fn matches_all(&self, value: &Value) -> bool {
        match self {
            Comparator::Equals(comparator) => comparator.matches_all(value),
            Comparator::Contains(comparator) => {
                comparator.matches_all(value, |haystack, needle| haystack.contains(needle))
            }
            Comparator::StartsWith(comparator) => {
                comparator.matches_all(value, |haystack, needle| haystack.starts_with(needle))
            }
            Comparator::EndsWith(comparator) => {
                comparator.matches_all(value, |haystack, needle| haystack.ends_with(needle))
            }
            Comparator::Regex(comparator) => comparator.matches_all(value),
            Comparator::Cidr(comparator) => comparator.matches_all(value),
            Comparator::Numeric(comparator) => comparator.matches_all(value),
        }
    }
}

#[derive(Clone, Debug)]
struct EqualityComparator {
    values: Vec<Value>,
    case_insensitive: bool,
}

impl EqualityComparator {
    fn matches_any(&self, value: &Value) -> bool {
        if self.case_insensitive {
            if let Some(actual) = value_to_string_lossy(value) {
                self.values.iter().any(|expected| {
                    value_to_string_lossy(expected)
                        .map_or(false, |expected| actual.eq_ignore_ascii_case(&expected))
                })
            } else {
                false
            }
        } else {
            self.values.iter().any(|expected| value == expected)
        }
    }

    fn matches_all(&self, value: &Value) -> bool {
        if self.case_insensitive {
            if let Some(actual) = value_to_string_lossy(value) {
                self.values.iter().all(|expected| {
                    value_to_string_lossy(expected)
                        .map_or(false, |expected| actual.eq_ignore_ascii_case(&expected))
                })
            } else {
                false
            }
        } else {
            self.values.iter().all(|expected| value == expected)
        }
    }
}

#[derive(Clone, Debug)]
struct StringComparator {
    values: Vec<String>,
    case_insensitive: bool,
}

impl StringComparator {
    fn matches_any<F>(&self, value: &Value, predicate: F) -> bool
    where
        F: Fn(&str, &str) -> bool,
    {
        let haystack = match value_to_string_lossy(value) {
            Some(actual) => {
                if self.case_insensitive {
                    actual.to_ascii_lowercase()
                } else {
                    actual
                }
            }
            None => return false,
        };

        self.values.iter().any(|needle| {
            if self.case_insensitive {
                predicate(&haystack, &needle.to_ascii_lowercase())
            } else {
                predicate(&haystack, needle)
            }
        })
    }

    fn matches_all<F>(&self, value: &Value, predicate: F) -> bool
    where
        F: Fn(&str, &str) -> bool,
    {
        let haystack = match value_to_string_lossy(value) {
            Some(actual) => {
                if self.case_insensitive {
                    actual.to_ascii_lowercase()
                } else {
                    actual
                }
            }
            None => return false,
        };

        self.values.iter().all(|needle| {
            if self.case_insensitive {
                predicate(&haystack, &needle.to_ascii_lowercase())
            } else {
                predicate(&haystack, needle)
            }
        })
    }
}

#[derive(Clone, Debug)]
struct RegexComparator {
    patterns: Vec<Regex>,
}

impl RegexComparator {
    fn matches_any(&self, value: &Value) -> bool {
        match value {
            Value::Bytes(bytes) => {
                let haystack = String::from_utf8_lossy(bytes.as_ref());
                self.patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&haystack))
            }
            _ => false,
        }
    }

    fn matches_all(&self, value: &Value) -> bool {
        match value {
            Value::Bytes(bytes) => {
                let haystack = String::from_utf8_lossy(bytes.as_ref());
                self.patterns
                    .iter()
                    .all(|pattern| pattern.is_match(&haystack))
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
struct CidrComparator {
    networks: Vec<IpNet>,
}

impl CidrComparator {
    fn matches_any(&self, value: &Value) -> bool {
        match parse_ip(value) {
            Some(address) => self
                .networks
                .iter()
                .any(|network| network.contains(&address)),
            None => false,
        }
    }

    fn matches_all(&self, value: &Value) -> bool {
        match parse_ip(value) {
            Some(address) => self
                .networks
                .iter()
                .all(|network| network.contains(&address)),
            None => false,
        }
    }
}

#[derive(Clone, Debug)]
struct NumericComparator {
    operator: NumericOperator,
    numbers: Vec<NumericValue>,
}

impl NumericComparator {
    fn matches_any(&self, value: &Value) -> bool {
        match numeric_from_value(value) {
            Some(actual) => self
                .numbers
                .iter()
                .any(|expected| self.operator.compare(actual, *expected)),
            None => false,
        }
    }

    fn matches_all(&self, value: &Value) -> bool {
        match numeric_from_value(value) {
            Some(actual) => self
                .numbers
                .iter()
                .all(|expected| self.operator.compare(actual, *expected)),
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum NumericOperator {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

impl NumericOperator {
    fn compare(self, actual: NumericValue, expected: NumericValue) -> bool {
        match (actual, expected) {
            (NumericValue::Integer(lhs), NumericValue::Integer(rhs)) => match self {
                NumericOperator::LessThan => lhs < rhs,
                NumericOperator::LessThanOrEqual => lhs <= rhs,
                NumericOperator::GreaterThan => lhs > rhs,
                NumericOperator::GreaterThanOrEqual => lhs >= rhs,
            },
            (NumericValue::Float(lhs), NumericValue::Float(rhs)) => match self {
                NumericOperator::LessThan => lhs < rhs,
                NumericOperator::LessThanOrEqual => lhs <= rhs,
                NumericOperator::GreaterThan => lhs > rhs,
                NumericOperator::GreaterThanOrEqual => lhs >= rhs,
            },
            (NumericValue::Integer(lhs), NumericValue::Float(rhs)) => match self {
                NumericOperator::LessThan => (lhs as f64) < rhs,
                NumericOperator::LessThanOrEqual => (lhs as f64) <= rhs,
                NumericOperator::GreaterThan => (lhs as f64) > rhs,
                NumericOperator::GreaterThanOrEqual => (lhs as f64) >= rhs,
            },
            (NumericValue::Float(lhs), NumericValue::Integer(rhs)) => match self {
                NumericOperator::LessThan => lhs < rhs as f64,
                NumericOperator::LessThanOrEqual => lhs <= rhs as f64,
                NumericOperator::GreaterThan => lhs > rhs as f64,
                NumericOperator::GreaterThanOrEqual => lhs >= rhs as f64,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum NumericValue {
    Integer(i64),
    Float(f64),
}

fn numeric_from_value(value: &Value) -> Option<NumericValue> {
    match value {
        Value::Integer(int) => Some(NumericValue::Integer(*int)),
        Value::Float(float) => Some(NumericValue::Float((*float).into_inner())),
        Value::Boolean(boolean) => Some(NumericValue::Integer(if *boolean { 1 } else { 0 })),
        Value::Bytes(bytes) => {
            let text = String::from_utf8_lossy(bytes.as_ref());
            if let Ok(int) = text.parse::<i64>() {
                Some(NumericValue::Integer(int))
            } else if let Ok(float) = text.parse::<f64>() {
                Some(NumericValue::Float(float))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_ip(value: &Value) -> Option<IpAddr> {
    value_to_string_lossy(value).and_then(|text| text.parse().ok())
}

fn value_to_string_lossy(value: &Value) -> Option<String> {
    match value {
        Value::Bytes(bytes) => Some(String::from_utf8_lossy(bytes.as_ref()).into_owned()),
        Value::Boolean(boolean) => Some(boolean.to_string()),
        Value::Integer(integer) => Some(integer.to_string()),
        Value::Float(float) => Some(float.to_string()),
        Value::Timestamp(timestamp) => Some(timestamp.to_string()),
        Value::Null => None,
        Value::Array(_) => None,
        Value::Object(_) => None,
        Value::Regex(_) => None,
    }
}

fn numeric_value_from_value(value: &Value, path: &Path) -> crate::Result<NumericValue> {
    match value {
        Value::Integer(int) => Ok(NumericValue::Integer(*int)),
        Value::Float(float) => Ok(NumericValue::Float((*float).into_inner())),
        Value::Boolean(boolean) => Ok(NumericValue::Integer(if *boolean { 1 } else { 0 })),
        Value::Bytes(bytes) => {
            let text = String::from_utf8(bytes.as_ref().to_vec()).map_err(|err| {
                invalid_data(
                    path,
                    format!("Numeric modifier requires UTF-8 value: {err}"),
                )
            })?;
            if let Ok(int) = text.parse::<i64>() {
                Ok(NumericValue::Integer(int))
            } else if let Ok(float) = text.parse::<f64>() {
                Ok(NumericValue::Float(float))
            } else {
                Err(invalid_data(
                    path,
                    format!("Unable to parse numeric value '{text}'"),
                ))
            }
        }
        _ => Err(invalid_data(
            path,
            "Numeric comparison requires integer or float values",
        )),
    }
}

fn build_predicate(
    field_name: &str,
    expected: Vec<Value>,
    path: &Path,
) -> crate::Result<SelectionPredicate> {
    let (base, modifiers) = parse_field_spec(field_name, path)?;
    let plan = compile_modifiers(&modifiers, path)?;
    let matcher = plan.build(expected, path)?;

    Ok(SelectionPredicate {
        path: base,
        matcher,
    })
}

fn parse_field_spec<'a>(field: &'a str, path: &Path) -> crate::Result<(String, Vec<&'a str>)> {
    let mut parts = field.split('|');
    let base = parts
        .next()
        .ok_or_else(|| invalid_data(path, "Sigma field definition cannot be empty"))?
        .trim();

    if base.is_empty() {
        return Err(invalid_data(
            path,
            "Sigma field definition must include a field name",
        ));
    }

    let modifiers = parts
        .map(str::trim)
        .filter(|modifier| !modifier.is_empty())
        .collect::<Vec<_>>();

    Ok((base.to_owned(), modifiers))
}

#[derive(Clone, Debug)]
struct ModifierPlan {
    comparator: ComparatorKind,
    aggregator: Aggregator,
    transforms: Vec<ValueTransform>,
}

impl ModifierPlan {
    fn build(self, expected: Vec<Value>, path: &Path) -> crate::Result<FieldMatcher> {
        let transformed = self
            .transforms
            .into_iter()
            .try_fold(expected, |values, transform| transform.apply(values, path))?;
        let comparator = self.comparator.build(transformed, path)?;
        Ok(FieldMatcher {
            comparator,
            aggregator: self.aggregator,
        })
    }
}

#[derive(Clone, Debug)]
enum ComparatorKind {
    Equals(CaseSensitivity),
    Contains(CaseSensitivity),
    StartsWith(CaseSensitivity),
    EndsWith(CaseSensitivity),
    Regex(RegexStyle),
    Cidr,
    Numeric(NumericOperator),
}

impl ComparatorKind {
    fn build(self, expected: Vec<Value>, path: &Path) -> crate::Result<Comparator> {
        match self {
            ComparatorKind::Equals(case) => Ok(Comparator::Equals(EqualityComparator {
                values: expected,
                case_insensitive: case == CaseSensitivity::Insensitive,
            })),
            ComparatorKind::Contains(case) => Ok(Comparator::Contains(StringComparator {
                values: values_to_strings(expected, path)?,
                case_insensitive: case == CaseSensitivity::Insensitive,
            })),
            ComparatorKind::StartsWith(case) => Ok(Comparator::StartsWith(StringComparator {
                values: values_to_strings(expected, path)?,
                case_insensitive: case == CaseSensitivity::Insensitive,
            })),
            ComparatorKind::EndsWith(case) => Ok(Comparator::EndsWith(StringComparator {
                values: values_to_strings(expected, path)?,
                case_insensitive: case == CaseSensitivity::Insensitive,
            })),
            ComparatorKind::Regex(style) => {
                let mut patterns = Vec::new();
                for pattern in values_to_strings(expected, path)? {
                    let mut builder = RegexBuilder::new(&pattern);
                    builder.case_insensitive(matches!(style, RegexStyle::Insensitive));
                    let regex = builder.build().map_err(|err| {
                        invalid_data(
                            path,
                            format!("Failed to compile regular expression '{pattern}': {err}"),
                        )
                    })?;
                    patterns.push(regex);
                }
                Ok(Comparator::Regex(RegexComparator { patterns }))
            }
            ComparatorKind::Cidr => {
                let mut networks = Vec::new();
                for cidr in values_to_strings(expected, path)? {
                    networks.push(cidr.parse::<IpNet>().map_err(|err| {
                        invalid_data(
                            path,
                            format!("Failed to parse CIDR network '{cidr}': {err}"),
                        )
                    })?);
                }
                Ok(Comparator::Cidr(CidrComparator { networks }))
            }
            ComparatorKind::Numeric(operator) => {
                let mut numbers = Vec::new();
                for value in expected.iter() {
                    numbers.push(numeric_value_from_value(value, path)?);
                }
                Ok(Comparator::Numeric(NumericComparator { operator, numbers }))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaseSensitivity {
    Sensitive,
    Insensitive,
}

#[derive(Clone, Copy, Debug)]
enum RegexStyle {
    Sensitive,
    Insensitive,
}

fn values_to_strings(values: Vec<Value>, path: &Path) -> crate::Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| match value {
            Value::Bytes(bytes) => String::from_utf8(bytes.as_ref().to_vec()).map_err(|err| {
                invalid_data(
                    path,
                    format!("Sigma expected string is not valid UTF-8: {err}"),
                )
            }),
            Value::Boolean(boolean) => Ok(boolean.to_string()),
            Value::Integer(integer) => Ok(integer.to_string()),
            Value::Float(float) => Ok(float.to_string()),
            Value::Timestamp(timestamp) => Ok(timestamp.to_string()),
            other => Err(invalid_data(
                path,
                format!("Unsupported value type {other:?} for string comparison"),
            )),
        })
        .collect()
}

fn compile_modifiers(modifiers: &[&str], path: &Path) -> crate::Result<ModifierPlan> {
    let mut comparator = ComparatorKind::Equals(CaseSensitivity::Sensitive);
    let mut aggregator = Aggregator::Any;
    let mut transforms = Vec::new();
    let mut comparator_set = false;

    for modifier in modifiers {
        let lower = modifier.to_ascii_lowercase();
        match lower.as_str() {
            "contains" => {
                comparator = ComparatorKind::Contains(CaseSensitivity::Sensitive);
                comparator_set = true;
            }
            "icontains" => {
                comparator = ComparatorKind::Contains(CaseSensitivity::Insensitive);
                comparator_set = true;
            }
            "startswith" => {
                comparator = ComparatorKind::StartsWith(CaseSensitivity::Sensitive);
                comparator_set = true;
            }
            "istartswith" => {
                comparator = ComparatorKind::StartsWith(CaseSensitivity::Insensitive);
                comparator_set = true;
            }
            "endswith" => {
                comparator = ComparatorKind::EndsWith(CaseSensitivity::Sensitive);
                comparator_set = true;
            }
            "iendswith" => {
                comparator = ComparatorKind::EndsWith(CaseSensitivity::Insensitive);
                comparator_set = true;
            }
            "equals" | "match" => {
                comparator = ComparatorKind::Equals(CaseSensitivity::Sensitive);
                comparator_set = true;
            }
            "iequals" => {
                comparator = ComparatorKind::Equals(CaseSensitivity::Insensitive);
                comparator_set = true;
            }
            "regex" | "re" => {
                comparator = ComparatorKind::Regex(RegexStyle::Sensitive);
                comparator_set = true;
            }
            "iregex" | "ire" => {
                comparator = ComparatorKind::Regex(RegexStyle::Insensitive);
                comparator_set = true;
            }
            "cidr" => {
                comparator = ComparatorKind::Cidr;
                comparator_set = true;
            }
            "lt" => {
                comparator = ComparatorKind::Numeric(NumericOperator::LessThan);
                comparator_set = true;
            }
            "lte" | "le" => {
                comparator = ComparatorKind::Numeric(NumericOperator::LessThanOrEqual);
                comparator_set = true;
            }
            "gt" => {
                comparator = ComparatorKind::Numeric(NumericOperator::GreaterThan);
                comparator_set = true;
            }
            "gte" | "ge" => {
                comparator = ComparatorKind::Numeric(NumericOperator::GreaterThanOrEqual);
                comparator_set = true;
            }
            "all" => aggregator = Aggregator::All,
            "any" => aggregator = Aggregator::Any,
            "wide" => transforms.push(ValueTransform::Wide),
            "utf16le" => transforms.push(ValueTransform::Utf16Le),
            "utf16be" => transforms.push(ValueTransform::Utf16Be),
            "utf8" => transforms.push(ValueTransform::Utf8),
            "ascii" => transforms.push(ValueTransform::Ascii),
            "base64" => transforms.push(ValueTransform::Base64),
            "base64offset" => transforms.push(ValueTransform::Base64Offset),
            "windash" => transforms.push(ValueTransform::WinDash),
            "lower" | "tolower" => transforms.push(ValueTransform::Lowercase),
            "upper" | "toupper" => transforms.push(ValueTransform::Uppercase),
            other => {
                return Err(invalid_data(
                    path,
                    format!("Unsupported Sigma match modifier '{other}'"),
                ));
            }
        }
    }

    if !comparator_set {
        comparator = ComparatorKind::Equals(CaseSensitivity::Sensitive);
    }

    Ok(ModifierPlan {
        comparator,
        aggregator,
        transforms,
    })
}

#[derive(Clone, Debug)]
enum ValueTransform {
    Wide,
    Utf16Le,
    Utf16Be,
    Utf8,
    Ascii,
    Base64,
    Base64Offset,
    WinDash,
    Lowercase,
    Uppercase,
}

impl ValueTransform {
    fn apply(&self, values: Vec<Value>, path: &Path) -> crate::Result<Vec<Value>> {
        match self {
            ValueTransform::Wide => values
                .into_iter()
                .map(|value| Self::apply_wide(value, path))
                .collect(),
            ValueTransform::Utf16Le => values
                .into_iter()
                .map(|value| Self::apply_utf16(value, path, Endianness::Little))
                .collect(),
            ValueTransform::Utf16Be => values
                .into_iter()
                .map(|value| Self::apply_utf16(value, path, Endianness::Big))
                .collect(),
            ValueTransform::Utf8 => values
                .into_iter()
                .map(|value| Self::apply_encoding(value, path, Encoding::Utf8))
                .collect(),
            ValueTransform::Ascii => values
                .into_iter()
                .map(|value| Self::apply_encoding(value, path, Encoding::Ascii))
                .collect(),
            ValueTransform::Base64 => values
                .into_iter()
                .map(|value| Self::apply_base64(value, path))
                .collect(),
            ValueTransform::Base64Offset => {
                let mut result = Vec::new();
                for value in values {
                    result.extend(Self::apply_base64_offset(value, path)?);
                }
                Ok(result)
            }
            ValueTransform::WinDash => values
                .into_iter()
                .map(|value| Self::apply_windash(value, path))
                .collect(),
            ValueTransform::Lowercase => values
                .into_iter()
                .map(|value| Self::apply_case(value, path, Case::Lower))
                .collect(),
            ValueTransform::Uppercase => values
                .into_iter()
                .map(|value| Self::apply_case(value, path, Case::Upper))
                .collect(),
        }
    }

    fn apply_wide(value: Value, path: &Path) -> crate::Result<Value> {
        let text = require_string(value, path)?;
        let mut encoded = String::with_capacity(text.len() * 2);
        for ch in text.chars() {
            encoded.push(ch);
            encoded.push('\0');
        }
        Ok(Value::from(encoded))
    }

    fn apply_utf16(value: Value, path: &Path, endianness: Endianness) -> crate::Result<Value> {
        let text = require_string(value, path)?;
        let mut bytes = Vec::with_capacity(text.len() * 2);
        for unit in text.encode_utf16() {
            match endianness {
                Endianness::Little => {
                    bytes.push((unit & 0xFF) as u8);
                    bytes.push((unit >> 8) as u8);
                }
                Endianness::Big => {
                    bytes.push((unit >> 8) as u8);
                    bytes.push((unit & 0xFF) as u8);
                }
            }
        }
        Ok(Value::Bytes(Bytes::from(bytes)))
    }

    fn apply_encoding(value: Value, path: &Path, encoding: Encoding) -> crate::Result<Value> {
        let text = require_string(value, path)?;
        let bytes = match encoding {
            Encoding::Utf8 => text.into_bytes(),
            Encoding::Ascii => {
                let mut buf = Vec::with_capacity(text.len());
                for ch in text.chars() {
                    if ch.is_ascii() {
                        buf.push(ch as u8);
                    } else {
                        return Err(invalid_data(
                            path,
                            "ASCII transformation requires ASCII characters",
                        ));
                    }
                }
                buf
            }
        };
        Ok(Value::Bytes(Bytes::from(bytes)))
    }

    fn apply_base64(value: Value, path: &Path) -> crate::Result<Value> {
        let bytes = require_bytes(value, path)?;
        Ok(Value::from(BASE64_STANDARD.encode(bytes)))
    }

    fn apply_base64_offset(value: Value, path: &Path) -> crate::Result<Vec<Value>> {
        let bytes = require_bytes(value, path)?;
        let mut encodings = Vec::new();
        for offset in 0..3 {
            if offset > bytes.len() {
                continue;
            }
            let slice = bytes[offset..].to_vec();
            encodings.push(Value::from(BASE64_STANDARD.encode(slice)));
        }
        Ok(encodings)
    }

    fn apply_windash(value: Value, path: &Path) -> crate::Result<Value> {
        let text = require_string(value, path)?;
        Ok(Value::from(text.replace('-', "\u{2212}")))
    }

    fn apply_case(value: Value, path: &Path, case: Case) -> crate::Result<Value> {
        let text = require_string(value, path)?;
        let transformed = match case {
            Case::Lower => text.to_ascii_lowercase(),
            Case::Upper => text.to_ascii_uppercase(),
        };
        Ok(Value::from(transformed))
    }
}

#[derive(Clone, Copy, Debug)]
enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug)]
enum Encoding {
    Utf8,
    Ascii,
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Lower,
    Upper,
}

fn require_string(value: Value, path: &Path) -> crate::Result<String> {
    match value {
        Value::Bytes(bytes) => String::from_utf8(bytes.as_ref().to_vec()).map_err(|err| {
            invalid_data(
                path,
                format!("Sigma expected string is not valid UTF-8: {err}"),
            )
        }),
        Value::Boolean(boolean) => Ok(boolean.to_string()),
        Value::Integer(integer) => Ok(integer.to_string()),
        Value::Float(float) => Ok(float.to_string()),
        Value::Timestamp(timestamp) => Ok(timestamp.to_string()),
        other => Err(invalid_data(
            path,
            format!("Unsupported value type {other:?} for string transformation"),
        )),
    }
}

fn require_bytes(value: Value, path: &Path) -> crate::Result<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.as_ref().to_vec()),
        Value::Boolean(boolean) => Ok(boolean.to_string().into_bytes()),
        Value::Integer(integer) => Ok(integer.to_string().into_bytes()),
        Value::Float(float) => Ok(float.to_string().into_bytes()),
        Value::Timestamp(timestamp) => Ok(timestamp.to_string().into_bytes()),
        other => Err(invalid_data(
            path,
            format!("Unsupported value type {other:?} for binary transformation"),
        )),
    }
}

fn yaml_scalar_to_value(path: &Path, field_name: &str, value: &YamlValue) -> crate::Result<Value> {
    match value {
        YamlValue::String(s) => Ok(Value::from(s.clone())),
        YamlValue::Number(num) => {
            if let Some(i) = num.as_i64() {
                Ok(Value::from(i))
            } else if let Some(u) = num.as_u64() {
                let converted = i64::try_from(u).map_err(|err| {
                    invalid_data(path, format!("Unsigned numeric value is too large: {err}"))
                })?;
                Ok(Value::from(converted))
            } else if let Some(f) = num.as_f64() {
                Ok(Value::from(f))
            } else {
                Err(invalid_data(
                    path,
                    format!(
                        "Selection field '{field_name}' contains a numeric value that cannot be represented"
                    ),
                ))
            }
        }
        YamlValue::Bool(b) => Ok(Value::from(*b)),
        YamlValue::Null => Err(invalid_data(
            path,
            format!("Selection field '{field_name}' does not support null values from Sigma rules"),
        )),
        other => Err(invalid_data(
            path,
            format!(
                "Selection field '{field_name}' requires a scalar or list of scalars (got {other:?})"
            ),
        )),
    }
}

fn invalid_data(path: &Path, message: impl Into<String>) -> crate::Error {
    let err = io::Error::new(io::ErrorKind::InvalidData, message.into());
    let err = io::Error::new(err.kind(), format!("{}: {err}", path.display()));
    crate::Error::from(err)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::config::TransformContext;
    use indoc::indoc;
    use tempfile::NamedTempFile;

    use super::*;

    mod event {
        pub use vector_lib::event::{Event, LogEvent, Value};
        pub use vector_lib::lookup::event_path;
    }

    use event::{Event, LogEvent, Value};

    async fn build_transform(rule: &str) -> Transform {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", rule).unwrap();

        let config = SigmaConfig {
            rules_files: vec![file.path().to_path_buf()],
        };

        config
            .build(&TransformContext::default())
            .await
            .expect("failed to build transform")
    }

    fn apply_transform(transform: &mut Transform, log: LogEvent) -> LogEvent {
        let event = Event::Log(log);
        let mut output = OutputBuffer::with_capacity(1);
        match transform {
            Transform::Function(function) => {
                function.transform(&mut output, event);
            }
            _ => panic!("sigma transform must be a function variant"),
        }
        let mut iter = output.into_events();
        let event = iter.next().expect("missing event");
        assert!(iter.next().is_none());
        event.into_log()
    }

    #[tokio::test]
    async fn sigma_matches_basic_selection() {
        let mut transform = build_transform(indoc! {r#"
            title: Basic
            detection:
              selection:
                message: suspicious
              condition: selection
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("message"), Value::from("suspicious"));
        let log = apply_transform(&mut transform, log);

        let matches = log
            .get(event::event_path!("sigma", "matches"))
            .expect("missing matches field");
        assert_eq!(matches, &Value::Array(vec![Value::from("Basic")]));
    }

    #[tokio::test]
    async fn sigma_supports_contains_modifier() {
        let mut transform = build_transform(indoc! {r#"
            title: Contains
            detection:
              selection_contains:
                field|contains: suspicious activity
              condition: selection_contains
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(
            event::event_path!("field"),
            Value::from("very suspicious activity detected"),
        );
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }

    #[tokio::test]
    async fn sigma_supports_case_insensitive_modifiers() {
        let mut transform = build_transform(indoc! {r#"
            title: Case insensitive
            detection:
              selection_case:
                field|icontains: admin
              condition: selection_case
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("field"), Value::from("ADMINISTRATOR"));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }

    #[tokio::test]
    async fn sigma_supports_numeric_modifiers() {
        let mut transform = build_transform(indoc! {r#"
            title: Numeric
            detection:
              selection_numeric:
                count|gt: 5
              condition: selection_numeric
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("count"), Value::from(10));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }

    #[tokio::test]
    async fn sigma_supports_regex_modifiers() {
        let mut transform = build_transform(indoc! {r#"
            title: Regex
            detection:
              selection_regex:
                field|regex: "^po.*shell$"
              condition: selection_regex
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("field"), Value::from("powershell"));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }

    #[tokio::test]
    async fn sigma_supports_condition_quantifiers() {
        let mut transform = build_transform(indoc! {r#"
            title: Quantifier
            detection:
              selection_one:
                message: foo
              selection_two:
                message: bar
              condition: 1 of selection*
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("message"), Value::from("foo"));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }

    #[tokio::test]
    async fn sigma_supports_condition_negation() {
        let mut transform = build_transform(indoc! {r#"
            title: Negation
            detection:
              selection_yes:
                field: yes
              selection_no:
                field: no
              condition: selection_yes and not selection_no
        "#})
        .await;

        let mut log = LogEvent::default();
        log.insert(event::event_path!("field"), Value::from("yes"));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());

        let mut log = LogEvent::default();
        log.insert(event::event_path!("field"), Value::from("no"));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_none());
    }

    #[tokio::test]
    async fn sigma_supports_base64_transform() {
        let mut transform = build_transform(indoc! {r#"
            title: Base64
            detection:
              selection_base64:
                field|base64|contains: secret
              condition: selection_base64
        "#})
        .await;

        let mut log = LogEvent::default();
        let encoded = BASE64_STANDARD.encode("my secret payload");
        log.insert(event::event_path!("field"), Value::from(encoded));
        let log = apply_transform(&mut transform, log);
        assert!(log.get(event::event_path!("sigma", "matches")).is_some());
    }
}
