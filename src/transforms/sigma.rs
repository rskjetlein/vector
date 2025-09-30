use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::LazyLock,
};

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
    pub fn new(rules: Vec<CompiledRule>) -> Self {
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
    disjunctions: Vec<Vec<usize>>,
}

impl CompiledRule {
    fn matches(&self, log: &LogEvent) -> bool {
        self.disjunctions.iter().any(|group| {
            group
                .iter()
                .all(|&selection_idx| self.selections[selection_idx].matches(log))
        })
    }

    fn try_from_raw(raw: RawSigmaRule, path: &Path, ordinal: usize) -> crate::Result<Self> {
        let (selections, name_map, condition) = parse_detection(raw.detection, path)?;
        let display_name = raw
            .title
            .or(raw.id)
            .unwrap_or_else(|| format!("{}#{}", path.display(), ordinal))
            .trim()
            .to_owned();

        let disjunctions = if let Some(condition) = condition {
            parse_condition(&condition, &name_map, path)?
        } else {
            selections
                .iter()
                .enumerate()
                .map(|(idx, _)| vec![idx])
                .collect()
        };

        if disjunctions.is_empty() {
            return Err(invalid_data(
                path,
                "Sigma rule must define at least one selection",
            ));
        }

        Ok(Self {
            display_name,
            selections,
            disjunctions,
        })
    }
}

#[derive(Clone, Debug)]
struct Selection {
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
    expected: String,
}

impl SelectionPredicate {
    fn matches(&self, log: &LogEvent) -> bool {
        match log.parse_path_and_get_value(&self.path) {
            Ok(Some(value)) => value.to_string_lossy() == self.expected,
            _ => false,
        }
    }
}

fn parse_detection(
    detection: YamlValue,
    path: &Path,
) -> crate::Result<(Vec<Selection>, HashMap<String, usize>, Option<String>)> {
    let mapping = detection
        .as_mapping()
        .ok_or_else(|| invalid_data(path, "Sigma rule detection section must be a mapping"))?;

    let mut selections = Vec::new();
    let mut name_map = HashMap::new();
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

        let selection_map = value.as_mapping().ok_or_else(|| {
            invalid_data(path, "Selection entries must be mappings of field to value")
        })?;

        let mut predicates = Vec::new();
        for (field_key, field_value) in selection_map {
            let field_name = field_key
                .as_str()
                .ok_or_else(|| invalid_data(path, "Selection field keys must be strings"))?;

            let expected = match field_value {
                YamlValue::String(s) => s.clone(),
                YamlValue::Number(num) => num.to_string(),
                YamlValue::Bool(b) => b.to_string(),
                other => {
                    return Err(invalid_data(
                        path,
                        format!(
                            "Selection values must be strings, numbers, or booleans (got {other:?})"
                        ),
                    ));
                }
            };

            predicates.push(SelectionPredicate {
                path: field_name.to_owned(),
                expected,
            });
        }

        let index = selections.len();
        name_map.insert(key.to_owned(), index);
        selections.push(Selection { predicates });
    }

    if selections.is_empty() {
        return Err(invalid_data(
            path,
            "Detection section must include at least one selection block",
        ));
    }

    Ok((selections, name_map, condition))
}

fn parse_condition(
    condition: &str,
    name_map: &HashMap<String, usize>,
    path: &Path,
) -> crate::Result<Vec<Vec<usize>>> {
    let mut disjunctions = Vec::new();
    let mut current = Vec::new();
    let mut expect_operand = true;

    for token in condition.split_whitespace() {
        if token.eq_ignore_ascii_case("and") {
            if expect_operand {
                return Err(invalid_data(
                    path,
                    "Condition cannot have 'and' without a selection",
                ));
            }
            expect_operand = true;
        } else if token.eq_ignore_ascii_case("or") {
            if expect_operand {
                return Err(invalid_data(
                    path,
                    "Condition cannot have 'or' without a selection",
                ));
            }
            if current.is_empty() {
                return Err(invalid_data(path, "Condition contains an empty clause"));
            }
            disjunctions.push(std::mem::take(&mut current));
            expect_operand = true;
        } else {
            let selection_idx = name_map.get(token).ok_or_else(|| {
                invalid_data(
                    path,
                    format!("Condition references unknown selection '{token}'"),
                )
            })?;
            current.push(*selection_idx);
            expect_operand = false;
        }
    }

    if expect_operand {
        return Err(invalid_data(
            path,
            "Condition must end with a selection name",
        ));
    }

    if !current.is_empty() {
        disjunctions.push(current);
    }

    Ok(disjunctions)
}

fn invalid_data(path: &Path, message: impl Into<String>) -> crate::Error {
    let err = io::Error::new(io::ErrorKind::InvalidData, message.into());
    let err = io::Error::new(err.kind(), format!("{}: {err}", path.display()));
    crate::Error::from(err)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use indoc::indoc;
    use tempfile::NamedTempFile;
    use vector_lib::{
        config::TransformContext,
        event::{Event, LogEvent, event_path},
    };

    use super::*;

    #[tokio::test]
    async fn sigma_transform_matches_event() {
        let mut rule_file = NamedTempFile::new().unwrap();
        write!(
            rule_file,
            "{}",
            indoc! {r#"
                title: Process creation
                detection:
                  selection:
                    message: suspicious
                  condition: selection
            "#}
        )
        .unwrap();

        let config = SigmaConfig {
            rules_files: vec![rule_file.path().to_path_buf()],
        };

        let transform = config
            .build(&TransformContext::default())
            .await
            .expect("failed to build transform");

        let mut transform = match transform {
            Transform::Function(function) => function,
            _ => panic!("expected function transform"),
        };

        let mut log = LogEvent::default();
        log.insert(event_path!("message"), Value::from("suspicious"));
        let event = Event::Log(log);

        let mut output = OutputBuffer::with_capacity(1);
        transform.transform(&mut output, event);

        let mut result = output.into_events();
        let event = result.next().expect("missing event");
        assert!(result.next().is_none());

        let matches = event
            .as_log()
            .get(event_path!("sigma", "matches"))
            .expect("missing matches field");
        assert_eq!(
            matches,
            &Value::Array(vec![Value::from("Process creation")])
        );
    }

    #[tokio::test]
    async fn sigma_transform_no_match_removes_field() {
        let mut rule_file = NamedTempFile::new().unwrap();
        write!(
            rule_file,
            "{}",
            indoc! {r#"
                title: Process creation
                detection:
                  selection:
                    message: suspicious
                  condition: selection
            "#}
        )
        .unwrap();

        let config = SigmaConfig {
            rules_files: vec![rule_file.path().to_path_buf()],
        };

        let transform = config
            .build(&TransformContext::default())
            .await
            .expect("failed to build transform");

        let mut transform = match transform {
            Transform::Function(function) => function,
            _ => panic!("expected function transform"),
        };

        let mut log = LogEvent::default();
        log.insert(event_path!("message"), Value::from("benign"));
        let event = Event::Log(log);

        let mut output = OutputBuffer::with_capacity(1);
        transform.transform(&mut output, event);

        let mut result = output.into_events();
        let event = result.next().expect("missing event");
        assert!(result.next().is_none());

        assert!(
            event
                .as_log()
                .get(event_path!("sigma", "matches"))
                .is_none()
        );
    }
}
