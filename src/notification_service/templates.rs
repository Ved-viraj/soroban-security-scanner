//! Template management system for notifications

use crate::notification_service::types::{
    NotificationChannel, NotificationTemplate, RenderedTemplate, TemplateContext, TemplateError,
    TemplateInfo, TemplateVariable, VariableType,
};
use handlebars::{Handlebars, TemplateRenderError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Template manager for handling notification templates
#[derive(Debug, Clone)]
pub struct TemplateManager {
    templates: HashMap<String, NotificationTemplate>,
    handlebars: Handlebars<'static>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new() -> Result<Self, TemplateError> {
        let mut handlebars = Handlebars::new();

        // Register custom helpers
        handlebars.register_helper("format_date", Box::new(format_date_helper));
        handlebars.register_helper("format_currency", Box::new(format_currency_helper));
        handlebars.register_helper("truncate", Box::new(truncate_helper));

        Ok(Self {
            templates: HashMap::new(),
            handlebars,
        })
    }

    /// Add a new template
    pub fn add_template(&mut self, template: NotificationTemplate) -> Result<(), TemplateError> {
        // Validate template syntax
        self.validate_template(&template)?;

        // Register with handlebars
        self.handlebars
            .register_template(&template.id, &template.body_template)?;

        if let Some(subject_template) = &template.subject_template {
            let subject_id = format!("{}_subject", template.id);
            self.handlebars
                .register_template(&subject_id, subject_template)?;
        }

        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// Update an existing template
    pub fn update_template(&mut self, template: NotificationTemplate) -> Result<(), TemplateError> {
        if !self.templates.contains_key(&template.id) {
            return Err(TemplateError::TemplateNotFound(template.id));
        }

        self.validate_template(&template)?;

        // Re-register with handlebars
        self.handlebars
            .register_template(&template.id, &template.body_template)?;

        if let Some(subject_template) = &template.subject_template {
            let subject_id = format!("{}_subject", template.id);
            self.handlebars
                .register_template(&subject_id, subject_template)?;
        }

        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// Get a template by ID
    pub fn get_template(&self, id: &str) -> Option<&NotificationTemplate> {
        self.templates.get(id)
    }

    /// List all templates
    pub fn list_templates(&self) -> Vec<&NotificationTemplate> {
        self.templates.values().collect()
    }

    /// Render a template with context
    pub fn render_template(
        &self,
        template_id: &str,
        context: &TemplateContext,
    ) -> Result<TemplateRender, TemplateError> {
        let template = self
            .templates
            .get(template_id)
            .ok_or_else(|| TemplateError::TemplateNotFound(template_id.to_string()))?;

        // Validate required variables
        self.validate_context(template, context)?;

        // Render body
        let body = self
            .handlebars
            .render(template_id, context)
            .map_err(|e| TemplateError::RenderError(e.to_string()))?;

        // Render subject if exists
        let subject = if let Some(_) = &template.subject_template {
            let subject_id = format!("{}_subject", template_id);
            Some(
                self.handlebars
                    .render(&subject_id, context)
                    .map_err(|e| TemplateError::RenderError(e.to_string()))?,
            )
        } else {
            None
        };

        Ok(TemplateRender {
            subject,
            body,
            template_id: template_id.to_string(),
        })
    }

    /// Render a template preview with the given context.
    /// Returns a RenderedTemplate with subject, plain-text body, and HTML body (for email templates).
    pub fn render_preview(
        &self,
        template_name: &str,
        context: &TemplateContext,
    ) -> Result<RenderedTemplate, TemplateError> {
        let rendered = self.render_template(template_name, context)?;
        let template = self
            .templates
            .get(template_name)
            .ok_or_else(|| TemplateError::TemplateNotFound(template_name.to_string()))?;

        // For email templates, generate an HTML version by wrapping the plain-text body
        // in a basic HTML structure if the template supports Email channel.
        let html_body = if template
            .supported_channels
            .contains(&NotificationChannel::Email)
        {
            Some(Self::plain_text_to_html(&rendered.subject, &rendered.body))
        } else {
            None
        };

        Ok(RenderedTemplate {
            subject: rendered.subject.clone(),
            plain_text_body: rendered.body.clone(),
            html_body,
            template_id: template_name.to_string(),
            template_name: template.name.clone(),
        })
    }

    /// List all templates with their metadata for the admin template listing endpoint.
    pub fn list_template_info(&self) -> Vec<TemplateInfo> {
        self.templates
            .values()
            .map(|t| TemplateInfo {
                id: t.id.clone(),
                name: t.name.clone(),
                description: t.description.clone(),
                supported_channels: t.supported_channels.clone(),
                variables: t.variables.clone(),
                version: t.version,
                active: t.active,
                created_at: t.created_at,
                updated_at: t.updated_at,
            })
            .collect()
    }

    /// Convert plain text to a basic HTML email body.
    /// Wraps the text in paragraphs and applies basic styling.
    fn plain_text_to_html(subject: &Option<String>, body: &str) -> String {
        let escaped_body = body
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let paragraphs: Vec<&str> = escaped_body
            .split("\n\n")
            .filter(|p| !p.is_empty())
            .collect();

        let body_html = if paragraphs.is_empty() {
            format!("<p>{}</p>", escaped_body.replace('\n', "<br>"))
        } else {
            paragraphs
                .iter()
                .map(|p| format!("<p>{}</p>", p.replace('\n', "<br>")))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let subject_line = subject
            .as_ref()
            .map(|s| format!("<h1>{}</h1>", s))
            .unwrap_or_default();

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Template Preview</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333; line-height: 1.6; }}
    h1 {{ color: #1a56db; font-size: 20px; }}
    p {{ margin: 0 0 12px 0; }}
    .footer {{ margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }}
  </style>
</head>
<body>
{}{}
  <div class="footer">
    <p>This is a preview of the template. Sent by Soroban Security Scanner.</p>
  </div>
</body>
</html>"#,
            subject_line, body_html
        )
    }

    /// Delete a template
    pub fn delete_template(&mut self, id: &str) -> Result<(), TemplateError> {
        if !self.templates.remove(id).is_some() {
            return Err(TemplateError::TemplateNotFound(id.to_string()));
        }

        self.handlebars.unregister_template(id);
        let subject_id = format!("{}_subject", id);
        self.handlebars.unregister_template(&subject_id);

        Ok(())
    }

    /// Validate template syntax
    fn validate_template(&self, template: &NotificationTemplate) -> Result<(), TemplateError> {
        // Basic syntax validation
        if template.body_template.is_empty() {
            return Err(TemplateError::InvalidTemplate(
                "Body template cannot be empty".to_string(),
            ));
        }

        // Check for required variables in template
        for variable in &template.variables {
            if variable.required {
                let placeholder = format!("{{{{{}}}}}", variable.name);
                if !template.body_template.contains(&placeholder) {
                    if let Some(subject) = &template.subject_template {
                        if !subject.contains(&placeholder) {
                            return Err(TemplateError::InvalidTemplate(format!(
                                "Required variable '{}' not found in template",
                                variable.name
                            )));
                        }
                    } else {
                        return Err(TemplateError::InvalidTemplate(format!(
                            "Required variable '{}' not found in template",
                            variable.name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate context against template requirements
    fn validate_context(
        &self,
        template: &NotificationTemplate,
        context: &TemplateContext,
    ) -> Result<(), TemplateError> {
        for variable in &template.variables {
            if variable.required && !context.contains_key(&variable.name) {
                if variable.default_value.is_none() {
                    return Err(TemplateError::MissingVariable(format!(
                        "Required variable '{}' is missing from context",
                        variable.name
                    )));
                }
            }
        }
        Ok(())
    }
}

impl Default for TemplateManager {
    fn default() -> Self {
        Self::new().expect("Failed to create TemplateManager")
    }
}

/// Rendered template result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRender {
    pub subject: Option<String>,
    pub body: String,
    pub template_id: String,
}

// Custom handlebars helpers
fn format_date_helper(
    h: &handlebars::Helper<'_, '_>,
    _: &handlebars::Handlebars<'_>,
    _: &handlebars::Context,
    _: &handlebars::RenderContext<'_, '_>,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    let param = h
        .param(0)
        .ok_or_else(|| handlebars::RenderError::new("Missing parameter"))?;
    let date_str = param
        .value()
        .as_str()
        .ok_or_else(|| handlebars::RenderError::new("Parameter must be a string"))?;

    // Simple date formatting - in a real implementation, use chrono
    let formatted = format!("Date: {}", date_str);
    out.write(&formatted)?;
    Ok(())
}

fn format_currency_helper(
    h: &handlebars::Helper<'_, '_>,
    _: &handlebars::Handlebars<'_>,
    _: &handlebars::Context,
    _: &handlebars::RenderContext<'_, '_>,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    let param = h
        .param(0)
        .ok_or_else(|| handlebars::RenderError::new("Missing parameter"))?;
    let amount = param
        .value()
        .as_f64()
        .ok_or_else(|| handlebars::RenderError::new("Parameter must be a number"))?;

    let formatted = format!("${:.2}", amount);
    out.write(&formatted)?;
    Ok(())
}

fn truncate_helper(
    h: &handlebars::Helper<'_, '_>,
    _: &handlebars::Handlebars<'_>,
    _: &handlebars::Context,
    _: &handlebars::RenderContext<'_, '_>,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    let text_param = h
        .param(0)
        .ok_or_else(|| handlebars::RenderError::new("Missing text parameter"))?;
    let length_param = h
        .param(1)
        .ok_or_else(|| handlebars::RenderError::new("Missing length parameter"))?;

    let text = text_param
        .value()
        .as_str()
        .ok_or_else(|| handlebars::RenderError::new("Text parameter must be a string"))?;
    let length = length_param
        .value()
        .as_u64()
        .ok_or_else(|| handlebars::RenderError::new("Length parameter must be a number"))?
        as usize;

    let truncated = if text.len() > length {
        format!("{}...", &text[..length])
    } else {
        text.to_string()
    };

    out.write(&truncated)?;
    Ok(())
}
