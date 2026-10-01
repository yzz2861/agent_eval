use std::ops::Deref;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::lookup_key::LookupPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportSourceKind {
    Input,
    Default,
    DefaultFactory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReportPathItem {
    Str(String),
    Pos(usize),
    Neg(usize),
}

impl ReportPathItem {
    fn into_py(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            Self::Str(value) => value.into_pyobject(py).map(Bound::unbind),
            Self::Pos(value) => value.into_pyobject(py).map(Bound::unbind),
            Self::Neg(value) => (-(value as i64)).into_pyobject(py).map(Bound::unbind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportPath {
    pub items: Vec<ReportPathItem>,
}

impl From<&LookupPath> for ReportPath {
    fn from(path: &LookupPath) -> Self {
        let mut items = Vec::with_capacity(1 + path.rest().len());
        items.push(ReportPathItem::Str(path.first_key().to_owned()));
        items.extend(path.rest().iter().map(|item| match item {
            crate::lookup_key::PathItem::S(key) => ReportPathItem::Str(key.deref().to_owned()),
            crate::lookup_key::PathItem::Pos(index) => ReportPathItem::Pos(*index),
            crate::lookup_key::PathItem::Neg(index) => ReportPathItem::Neg(*index),
        }));
        Self { items }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReportSource {
    kind: ReportSourceKind,
    path: Option<ReportPath>,
}

#[derive(Debug, Clone)]
pub(crate) enum ReportValue {
    Model {
        branch: Option<usize>,
        fields: Vec<(String, ReportField)>,
    },
    List {
        branch: Option<usize>,
        items: Vec<Option<ReportField>>,
    },
    Scalar {
        branch: Option<usize>,
    },
}

impl ReportValue {
    fn set_branch(&mut self, branch: usize) {
        match self {
            Self::Model { branch: current, .. }
            | Self::List { branch: current, .. }
            | Self::Scalar { branch: current } => *current = Some(branch),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReportField {
    name: Option<String>,
    field: ReportFieldInner,
}

#[derive(Debug, Clone, Default)]
struct ReportFieldInner {
    sources: Vec<ReportSource>,
    unconsumed_aliases: Vec<ReportPath>,
    value: Option<ReportValue>,
}

#[derive(Debug, Clone)]
enum ReportNode {
    Field(ReportField),
    Model(Vec<(String, ReportField)>),
    List(Vec<Option<ReportField>>),
}

#[derive(Debug, Clone)]
struct ReportFrame {
    node: ReportNode,
    list_index: Option<usize>,
    pending_branch: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidationReportCollector {
    root: Option<ReportNode>,
    stack: Vec<ReportFrame>,
}

pub(crate) struct ReportModelGuard(pub Option<ValidationReportCollector>);

impl ReportModelGuard {
    pub fn finish(mut self) -> Option<ValidationReportCollector> {
        let mut collector = self.0.take()?;
        collector.exit_model();
        Some(collector)
    }
}

impl Drop for ReportModelGuard {
    fn drop(&mut self) {
        if let Some(collector) = self.0.as_mut() {
            collector.exit_model();
        }
    }
}

pub(crate) struct ReportFieldGuard(pub Option<ValidationReportCollector>);

impl ReportFieldGuard {
    pub fn finish(mut self) -> Option<ValidationReportCollector> {
        let mut collector = self.0.take()?;
        collector.exit_field();
        Some(collector)
    }
}

impl Drop for ReportFieldGuard {
    fn drop(&mut self) {
        if let Some(collector) = self.0.as_mut() {
            collector.exit_field();
        }
    }
}

impl ReportFieldGuard {
    pub fn start(state_report: &mut Option<ValidationReportCollector>, name: &str) -> Option<Self> {
        let mut collector = state_report.take()?;
        collector.enter_field(name);
        Some(Self(Some(collector)))
    }
}

pub(crate) struct ReportListGuard(pub Option<ValidationReportCollector>);

impl ReportListGuard {
    pub fn finish(mut self) -> Option<ValidationReportCollector> {
        let mut collector = self.0.take()?;
        collector.exit_list();
        Some(collector)
    }
}

impl Drop for ReportListGuard {
    fn drop(&mut self) {
        if let Some(collector) = self.0.as_mut() {
            collector.exit_list();
        }
    }
}

#[derive(Debug, Clone)]
struct ReportSnapshot {
    collector: ValidationReportCollector,
}

impl ReportSnapshot {
    fn take(self) -> ValidationReportCollector {
        self.collector
    }
}

impl ValidationReportCollector {
    pub fn new() -> Self {
        Self {
            root: Some(ReportNode::Model(Vec::new())),
            stack: Vec::new(),
        }
    }

    pub fn enter_model(&mut self) {
        self.stack.push(ReportFrame {
            node: ReportNode::Model(Vec::new()),
            list_index: None,
            pending_branch: None,
        });
    }

    pub fn exit_model(&mut self) {
        self.exit_node();
    }

    pub fn enter_field(&mut self, name: &str) {
        self.stack.push(ReportFrame {
            node: ReportNode::Field(ReportField {
                name: Some(name.to_owned()),
                field: ReportFieldInner::default(),
            }),
            list_index: None,
            pending_branch: None,
        });
    }

    pub fn exit_field(&mut self) {
        self.exit_node();
    }

    pub fn enter_list(&mut self, length: usize) {
        self.stack.push(ReportFrame {
            node: ReportNode::List(vec![None; length]),
            list_index: None,
            pending_branch: None,
        });
    }

    pub fn enter_list_item(&mut self, index: usize) {
        if !matches!(self.stack.last().map(|frame| &frame.node), Some(ReportNode::List(_))) {
            return;
        }
        self.stack.push(ReportFrame {
            node: ReportNode::Field(ReportField {
                name: None,
                field: ReportFieldInner {
                    sources: vec![ReportSource {
                        kind: ReportSourceKind::Input,
                        path: Some(ReportPath {
                            items: vec![ReportPathItem::Pos(index)],
                        }),
                    }],
                    unconsumed_aliases: Vec::new(),
                    value: None,
                },
            }),
            list_index: Some(index),
            pending_branch: None,
        });
    }

    pub fn exit_list_item(&mut self) {
        if !matches!(
            self.stack.last(),
            Some(ReportFrame {
                list_index: Some(_),
                ..
            })
        ) {
            return;
        }
        self.exit_node();
    }

    pub fn exit_list(&mut self) {
        self.exit_node();
    }

    pub fn mark_list(&mut self, length: usize) {
        self.enter_list(length);
        for index in 0..length {
            self.enter_list_item(index);
            self.exit_list_item();
        }
        self.exit_list();
    }

    pub fn record_input(&mut self, path: Option<&LookupPath>) {
        self.record_source(ReportSourceKind::Input, path);
    }

    pub fn record_default(&mut self) {
        self.record_source(ReportSourceKind::Default, None);
    }

    pub fn record_default_factory(&mut self) {
        self.record_source(ReportSourceKind::DefaultFactory, None);
    }

    pub fn record_unconsumed_aliases<'a>(
        &mut self,
        selected: Option<&LookupPath>,
        aliases: impl Iterator<Item = &'a LookupPath>,
    ) {
        let Some(ReportNode::Field(report_field)) = self.current_node_mut() else {
            return;
        };
        report_field.field.unconsumed_aliases.extend(
            aliases
                .filter(|path| selected.is_none_or(|selected| !same_path(selected, path)))
                .map(ReportPath::from),
        );
    }

    pub fn set_branch(&mut self, branch: usize) {
        if let Some(frame) = self.stack.last_mut() {
            match &mut frame.node {
                ReportNode::Field(report_field) => {
                    report_field
                        .field
                        .value
                        .get_or_insert(ReportValue::Scalar { branch: None })
                        .set_branch(branch);
                }
                _ => frame.pending_branch = Some(branch),
            }
        }
    }

    pub fn snapshot(&self) -> ReportSnapshot {
        ReportSnapshot {
            collector: self.clone(),
        }
    }

    pub fn restore(&mut self, snapshot: ReportSnapshot) {
        *self = snapshot.collector;
    }

    pub fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        if let Some(node) = self.root {
            node_to_dict(py, &dict, &node)?;
        }
        Ok(dict.unbind())
    }

    fn current_node_mut(&mut self) -> Option<&mut ReportNode> {
        self.stack.last_mut().map(|frame| &mut frame.node)
    }

    fn record_source(&mut self, kind: ReportSourceKind, path: Option<&LookupPath>) {
        let Some(ReportNode::Field(report_field)) = self.current_node_mut() else {
            return;
        };
        report_field.field.sources.push(ReportSource {
            kind,
            path: path.map(ReportPath::from),
        });
    }

    fn exit_node(&mut self) {
        let Some(mut frame) = self.stack.pop() else {
            return;
        };
        let branch = frame.pending_branch;
        if let ReportNode::Field(report_field) = &mut frame.node
            && let Some(branch) = branch
        {
            report_field
                .field
                .value
                .get_or_insert(ReportValue::Scalar { branch: None })
                .set_branch(branch);
        }
        let node = frame.node;
        let index = frame.list_index;
        match self.stack.last_mut() {
            Some(parent) => attach_node(&mut parent.node, node, index, branch),
            None => self.root = Some(node),
        }
    }
}

fn attach_node(parent: &mut ReportNode, node: ReportNode, list_index: Option<usize>, branch: Option<usize>) {
    match (parent, node) {
        (ReportNode::Field(parent_field), node) => match node {
            ReportNode::Model(fields) => {
                let branch = branch.or_else(|| scalar_branch(parent_field));
                parent_field.field.value = Some(ReportValue::Model { branch, fields });
            }
            ReportNode::List(items) => {
                let branch = branch.or_else(|| scalar_branch(parent_field));
                parent_field.field.value = Some(ReportValue::List { branch, items });
            }
            ReportNode::Field(child) => {
                let branch = scalar_branch(&child);
                if let Some(branch) = branch {
                    parent_field
                        .field
                        .value
                        .get_or_insert(ReportValue::Scalar { branch: None })
                        .set_branch(branch);
                } else {
                    parent_field.field.value.get_or_insert(ReportValue::Scalar { branch: None });
                }
            }
        },
        (ReportNode::Model(fields), ReportNode::Field(child)) => {
            if let Some(name) = child.name.clone()
                && !fields.iter().any(|(field_name, _)| field_name == &name)
            {
                fields.push((name, child));
            }
        },
        (ReportNode::List(items), ReportNode::Field(child)) => {
            if let Some(index) = list_index
                && index < items.len()
            {
                items[index] = Some(child);
            }
        },
        _ => {}
    }
}

fn scalar_branch(field: &ReportField) -> Option<usize> {
    match &field.field.value {
        Some(ReportValue::Scalar { branch }) => *branch,
        _ => None,
    }
}

fn same_path(left: &LookupPath, right: &LookupPath) -> bool {
    ReportPath::from(left) == ReportPath::from(right)
}

fn node_to_dict(py: Python<'_>, dict: &Bound<'_, PyDict>, node: &ReportNode) -> PyResult<()> {
    match node {
        ReportNode::Field(field) => field_to_dict(py, dict, field, None)?,
        ReportNode::Model(fields) => {
            let fields_dict = PyDict::new(py);
            for (name, field) in fields {
                let field_dict = PyDict::new(py);
                field_to_dict(py, &field_dict, field, None)?;
                fields_dict.set_item(name, field_dict)?;
            }
            dict.set_item("fields", fields_dict)?;
        }
        ReportNode::List(items) => {
            let values = PyList::empty(py);
            for item in items {
                match item {
                    Some(field) => {
                        let item_dict = PyDict::new(py);
                        field_to_dict(py, &item_dict, field, None)?;
                        values.append(item_dict)?;
                    }
                    None => values.append(py.None())?,
                }
            }
            dict.set_item("items", values)?;
        }
    }
    Ok(())
}

fn field_to_dict(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
    field: &ReportField,
    branch_override: Option<usize>,
) -> PyResult<()> {
    let value = PyDict::new(py);
    let sources = PyList::empty(py);
    for source in &field.field.sources {
        let source_dict = PyDict::new(py);
        source_dict.set_item("type", source_name(source.kind))?;
        if let Some(path) = &source.path {
            source_dict.set_item("path", report_path_to_py(py, path)?)?;
        }
        sources.append(source_dict)?;
    }
    value.set_item("sources", sources)?;
    if !field.field.unconsumed_aliases.is_empty() {
        let aliases = PyList::empty(py);
        for path in &field.field.unconsumed_aliases {
            aliases.append(report_path_to_py(py, path)?)?;
        }
        value.set_item("unconsumed_aliases", aliases)?;
    }
    match &field.field.value {
        Some(ReportValue::Model { branch, fields }) => {
            if let Some(branch) = branch_override.or(*branch) {
                value.set_item("union_choice", branch)?;
            }
            let fields_dict = PyDict::new(py);
            for (name, nested_field) in fields {
                let field_dict = PyDict::new(py);
                field_to_dict(py, &field_dict, nested_field, None)?;
                fields_dict.set_item(name, field_dict)?;
            }
            value.set_item("fields", fields_dict)?;
        }
        Some(ReportValue::List { branch, items }) => {
            if let Some(branch) = branch_override.or(*branch) {
                value.set_item("union_choice", branch)?;
            }
            let values = PyList::empty(py);
            for item in items {
                match item {
                    Some(item_field) => {
                        let item_dict = PyDict::new(py);
                        field_to_dict(py, &item_dict, item_field, None)?;
                        values.append(item_dict)?;
                    }
                    None => values.append(py.None())?,
                }
            }
            value.set_item("items", values)?;
        }
        Some(ReportValue::Scalar { branch }) => {
            if let Some(branch) = branch_override.or(*branch) {
                value.set_item("union_choice", branch)?;
            }
        }
        None => {
            if let Some(branch) = branch_override {
                value.set_item("union_choice", branch)?;
            }
        }
    }
    dict.set_item("value", value)?;
    Ok(())
}

fn report_path_to_py(py: Python<'_>, path: &ReportPath) -> PyResult<Py<PyList>> {
    let items = PyList::empty(py);
    for item in &path.items {
        items.append(item.clone().into_py(py)?)?;
    }
    Ok(items.unbind())
}

fn source_name(kind: ReportSourceKind) -> &'static str {
    match kind {
        ReportSourceKind::Input => "input",
        ReportSourceKind::Default => "default",
        ReportSourceKind::DefaultFactory => "default_factory",
    }
}
