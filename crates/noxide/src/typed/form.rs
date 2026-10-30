use super::{action::ActionType, query::FromRequest};
use crate::RequestView;
use noxide_protocol::{Container, Control, FormInstruction};
use std::{marker::PhantomData, ops::Deref};
pub struct Form<A> {
    available: bool,
    marker: PhantomData<A>,
}
impl<A: ActionType> FromRequest for Form<A> {
    fn from_request(request: &RequestView) -> Self {
        Self {
            available: request.available_forms.contains(&A::definition().id),
            marker: PhantomData,
        }
    }
}
impl<A> Form<A> {
    pub fn is_available(&self) -> bool {
        self.available
    }
}

pub struct FormFields<A: ActionType> {
    controls: A::Controls,
}
impl<A: ActionType> Default for FormFields<A> {
    fn default() -> Self {
        Self::new()
    }
}
impl<A: ActionType> FormFields<A> {
    pub fn new() -> Self {
        Self {
            controls: A::controls(),
        }
    }
    pub fn submit(&self, label: impl Into<String>) -> FormLayout {
        FormLayout {
            instructions: vec![FormInstruction::Submit {
                label: label.into(),
            }],
        }
    }
}
impl<A: ActionType> Deref for FormFields<A> {
    type Target = A::Controls;
    fn deref(&self) -> &Self::Target {
        &self.controls
    }
}
#[derive(Clone, Default)]
pub struct FormLayout {
    #[doc(hidden)]
    pub instructions: Vec<FormInstruction>,
}
impl FormLayout {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&mut self, c: Container) {
        self.instructions.push(FormInstruction::Begin(c));
    }
    pub fn end(&mut self) {
        self.instructions.push(FormInstruction::End);
    }
    pub fn text(&mut self, text: impl ToString) {
        self.instructions
            .push(FormInstruction::Text(text.to_string()));
    }
    pub fn append(&mut self, other: Self) {
        self.instructions.extend(other.instructions);
    }
    pub fn rows(mut self, rows: u8) -> Self {
        if let [
            FormInstruction::Field {
                control: Control::Textarea { rows: old },
                ..
            },
        ] = self.instructions.as_mut_slice()
        {
            *old = rows;
        } else {
            panic!("rows applies to textarea controls");
        }
        self
    }
}
pub struct ControlField<T> {
    key: &'static str,
    marker: PhantomData<fn() -> T>,
}
impl<T> Copy for ControlField<T> {}
impl<T> Clone for ControlField<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> ControlField<T> {
    pub const fn new(key: &'static str) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }
    fn control(self, control: Control) -> FormLayout {
        FormLayout {
            instructions: vec![FormInstruction::Field {
                name: self.key.into(),
                control,
            }],
        }
    }
}
pub trait TextControl {}
impl TextControl for String {}
impl TextControl for super::resource::AccountId {}
impl TextControl for i64 {}
impl<T: TextControl> TextControl for Option<T> {}
pub trait TextareaValue {}
impl TextareaValue for String {}
impl TextareaValue for Option<String> {}
pub trait SelectValue {}
impl SelectValue for Option<bool> {}
impl<T: SelectValue> SelectValue for Option<T> {}
impl<T: TextControl> ControlField<T> {
    pub fn text_input(self) -> FormLayout {
        self.control(Control::TextInput)
    }
}
impl<T: TextareaValue> ControlField<T> {
    pub fn textarea(self) -> FormLayout {
        self.control(Control::Textarea { rows: 4 })
    }
}
impl ControlField<bool> {
    pub fn checkbox(self) -> FormLayout {
        self.control(Control::Checkbox)
    }
}
impl<T: SelectValue> ControlField<T> {
    pub fn select(self) -> FormLayout {
        self.control(Control::Select)
    }
}
