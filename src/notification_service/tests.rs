//! Tests for the notification service

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification_service::{
        NotificationChannel, NotificationMessage, NotificationPreferences, NotificationPriority,
        NotificationService, NotificationTemplate, Recipient, TemplateContext, TemplateVariable,
        VariableType,
    };
    use chrono::Utc;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_notification_service_creation() {
        let service = NotificationService::new();
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_template_management() {
        let service = NotificationService::new().unwrap();

        // Create a test template
        let template = NotificationTemplate {
            id: "test_template".to_string(),
            name: "Test Template".to_string(),
            description: Some("A test template".to_string()),
            subject_template: Some("Hello {{name}}".to_string()),
            body_template: "Welcome {{name}}! Your scan {{scan_id}} is {{status}}.".to_string(),
            supported_channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            default_priority: NotificationPriority::Normal,
            variables: vec![
                TemplateVariable {
                    name: "name".to_string(),
                    description: Some("User name".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "scan_id".to_string(),
                    description: Some("Scan ID".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "status".to_string(),
                    description: Some("Scan status".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        // Add template
        let result = service.add_template(template.clone()).await;
        assert!(result.is_ok());

        // Get template
        let retrieved = service.get_template("test_template").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Template");

        // List templates
        let templates = service.list_templates().await.unwrap();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].id, "test_template");
    }

    #[tokio::test]
    async fn test_template_rendering() {
        let service = NotificationService::new().unwrap();

        let template = NotificationTemplate {
            id: "render_test".to_string(),
            name: "Render Test".to_string(),
            description: None,
            subject_template: Some("Scan {{status}} for {{name}}".to_string()),
            body_template: "Hello {{name}},\n\nYour scan {{scan_id}} has completed with status: {{status}}.\n\n{{#if critical}}This requires immediate attention!{{/if}}".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![
                TemplateVariable {
                    name: "name".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "scan_id".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "status".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "critical".to_string(),
                    description: None,
                    required: false,
                    default_value: Some("false".to_string()),
                    variable_type: VariableType::Boolean,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        let mut context = TemplateContext::new();
        context.insert("name".to_string(), "John Doe".to_string());
        context.insert("scan_id".to_string(), "scan_123".to_string());
        context.insert("status".to_string(), "completed".to_string());
        context.insert("critical".to_string(), "true".to_string());

        let result = service
            .send_templated_notification(
                "render_test",
                create_test_recipient(),
                context,
                vec![NotificationChannel::InApp],
                NotificationPriority::Normal,
            )
            .await;

        assert!(result.is_ok());
        let notification_result = result.unwrap();
        assert!(notification_result.success);
    }

    #[tokio::test]
    async fn test_send_notification() {
        let service = NotificationService::new().unwrap();

        let message = NotificationMessage {
            id: "test_msg_1".to_string(),
            template_id: None,
            subject: Some("Test Notification".to_string()),
            body: "This is a test notification message.".to_string(),
            data: HashMap::new(),
            priority: NotificationPriority::Normal,
            channels: vec![NotificationChannel::InApp],
            created_at: Utc::now(),
            scheduled_for: None,
        };

        let recipient = create_test_recipient();

        let result = service.send_notification(message, recipient).await;
        assert!(result.is_ok());

        let notification_result = result.unwrap();
        assert!(notification_result.success);
        assert_eq!(notification_result.delivered_channels.len(), 1);
        assert_eq!(
            notification_result.delivered_channels[0],
            NotificationChannel::InApp
        );
    }

    #[tokio::test]
    async fn test_multiple_channels() {
        let service = NotificationService::new().unwrap();

        let message = NotificationMessage {
            id: "multi_channel_msg".to_string(),
            template_id: None,
            subject: Some("Multi-channel Test".to_string()),
            body: "Testing multiple notification channels.".to_string(),
            data: HashMap::new(),
            priority: NotificationPriority::Normal,
            channels: vec![
                NotificationChannel::InApp,
                NotificationChannel::Email,
                NotificationChannel::SMS,
            ],
            created_at: Utc::now(),
            scheduled_for: None,
        };

        let recipient = create_test_recipient();

        let result = service.send_notification(message, recipient).await;
        assert!(result.is_ok());

        let notification_result = result.unwrap();
        // Should succeed for InApp (enabled) but fail for Email/SMS (disabled by default)
        assert!(notification_result.success);
        assert!(notification_result
            .delivered_channels
            .contains(&NotificationChannel::InApp));
    }

    #[tokio::test]
    async fn test_priority_handling() {
        let service = NotificationService::new().unwrap();

        // Test critical priority bypasses quiet hours
        let message = NotificationMessage {
            id: "critical_msg".to_string(),
            template_id: None,
            subject: Some("Critical Alert".to_string()),
            body: "This is a critical notification.".to_string(),
            data: HashMap::new(),
            priority: NotificationPriority::Critical,
            channels: vec![NotificationChannel::InApp],
            created_at: Utc::now(),
            scheduled_for: None,
        };

        let mut recipient = create_test_recipient();
        // Set quiet hours
        recipient.preferences.quiet_hours = Some(crate::notification_service::types::QuietHours {
            start_hour: 22,
            end_hour: 8,
            timezone: "UTC".to_string(),
        });

        let result = service.send_notification(message, recipient).await;
        assert!(result.is_ok());

        let notification_result = result.unwrap();
        assert!(notification_result.success); // Critical should bypass quiet hours
    }

    #[tokio::test]
    async fn test_health_check() {
        let service = NotificationService::new().unwrap();

        let health_status = service.health_check().await;
        assert!(!health_status.is_empty());

        // InApp should be healthy (enabled by default)
        assert_eq!(health_status.get(&NotificationChannel::InApp), Some(&true));

        // Others should be unhealthy (disabled by default)
        assert_eq!(health_status.get(&NotificationChannel::Email), Some(&false));
        assert_eq!(health_status.get(&NotificationChannel::SMS), Some(&false));
        assert_eq!(health_status.get(&NotificationChannel::Push), Some(&false));
    }

    #[tokio::test]
    async fn test_provider_stats() {
        let service = NotificationService::new().unwrap();

        let stats = service.get_provider_stats().await;
        assert_eq!(stats.len(), 4); // All four channels

        // Check that all channels are present
        assert!(stats.contains_key(&NotificationChannel::Email));
        assert!(stats.contains_key(&NotificationChannel::SMS));
        assert!(stats.contains_key(&NotificationChannel::Push));
        assert!(stats.contains_key(&NotificationChannel::InApp));
    }

    #[tokio::test]
    async fn test_delivery_tracking() {
        let service = NotificationService::new().unwrap();

        let message = NotificationMessage {
            id: "tracking_test".to_string(),
            template_id: None,
            subject: Some("Tracking Test".to_string()),
            body: "Testing delivery tracking.".to_string(),
            data: HashMap::new(),
            priority: NotificationPriority::Normal,
            channels: vec![NotificationChannel::InApp],
            created_at: Utc::now(),
            scheduled_for: None,
        };

        let recipient = create_test_recipient();

        // Send notification
        let result = service.send_notification(message, recipient).await.unwrap();
        assert!(result.success);

        // Check tracking
        let tracking = service
            .get_delivery_tracking(
                "tracking_test",
                "test_recipient_1",
                NotificationChannel::InApp,
            )
            .await
            .unwrap();

        assert!(tracking.is_some());
        let tracking_info = tracking.unwrap();
        assert_eq!(tracking_info.notification_id, "tracking_test");
        assert_eq!(tracking_info.recipient_id, "test_recipient_1");
        assert_eq!(tracking_info.channel, NotificationChannel::InApp);
    }

    #[tokio::test]
    async fn test_delivery_stats() {
        let service = NotificationService::new().unwrap();

        // Send a few notifications to generate stats
        for i in 0..3 {
            let message = NotificationMessage {
                id: format!("stats_test_{}", i),
                template_id: None,
                subject: Some("Stats Test".to_string()),
                body: format!("Testing stats generation {}", i),
                data: HashMap::new(),
                priority: NotificationPriority::Normal,
                channels: vec![NotificationChannel::InApp],
                created_at: Utc::now(),
                scheduled_for: None,
            };

            let recipient = create_test_recipient();
            service.send_notification(message, recipient).await.unwrap();
        }

        let start_time = Utc::now() - chrono::Duration::hours(1);
        let end_time = Utc::now() + chrono::Duration::hours(1);

        let stats = service
            .get_delivery_stats(start_time, end_time)
            .await
            .unwrap();
        assert_eq!(stats.total_notifications, 3);
    }

    #[tokio::test]
    async fn test_template_validation() {
        let service = NotificationService::new().unwrap();

        // Test template with missing required variable
        let invalid_template = NotificationTemplate {
            id: "invalid_template".to_string(),
            name: "Invalid Template".to_string(),
            description: None,
            subject_template: Some("Hello {{name}}".to_string()),
            body_template: "This template has {{missing_variable}}".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![TemplateVariable {
                name: "name".to_string(),
                description: None,
                required: true,
                default_value: None,
                variable_type: VariableType::String,
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        let result = service.add_template(invalid_template).await;
        assert!(result.is_err()); // Should fail validation
    }

    #[tokio::test]
    async fn test_recipient_preferences() {
        let service = NotificationService::new().unwrap();

        let message = NotificationMessage {
            id: "preferences_test".to_string(),
            template_id: None,
            subject: Some("Preferences Test".to_string()),
            body: "Testing recipient preferences.".to_string(),
            data: HashMap::new(),
            priority: NotificationPriority::Normal,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            created_at: Utc::now(),
            scheduled_for: None,
        };

        // Create recipient with disabled email
        let mut recipient = create_test_recipient();
        recipient.preferences.email_enabled = false;

        let result = service.send_notification(message, recipient).await.unwrap();

        // Should only succeed for InApp (Email is disabled)
        assert!(result.success);
        assert!(result
            .delivered_channels
            .contains(&NotificationChannel::InApp));
        assert!(!result
            .delivered_channels
            .contains(&NotificationChannel::Email));

        // Should have failed channel for Email
        let email_failed = result
            .failed_channels
            .iter()
            .any(|(channel, _)| *channel == NotificationChannel::Email);
        assert!(email_failed);
    }

    fn create_test_recipient() -> Recipient {
        Recipient {
            id: "test_recipient_1".to_string(),
            email: Some("test@example.com".to_string()),
            phone: Some("+1234567890".to_string()),
            device_tokens: vec!["device_token_123".to_string()],
            user_id: Some("user_123".to_string()),
            preferences: NotificationPreferences::default(),
        }
    }

    #[tokio::test]
    async fn test_template_update() {
        let service = NotificationService::new().unwrap();

        // Create initial template
        let mut template = NotificationTemplate {
            id: "update_test".to_string(),
            name: "Original Template".to_string(),
            description: None,
            subject_template: Some("Original Subject".to_string()),
            body_template: "Original body content.".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template.clone()).await.unwrap();

        // Update template
        template.name = "Updated Template".to_string();
        template.body_template = "Updated body content.".to_string();
        template.version = 2;
        template.updated_at = Utc::now();

        let result = service.update_template(template).await;
        assert!(result.is_ok());

        // Verify update
        let updated = service.get_template("update_test").await.unwrap().unwrap();
        assert_eq!(updated.name, "Updated Template");
        assert_eq!(updated.version, 2);
    }

    #[tokio::test]
    async fn test_template_deletion() {
        let service = NotificationService::new().unwrap();

        let template = NotificationTemplate {
            id: "delete_test".to_string(),
            name: "Delete Test".to_string(),
            description: None,
            subject_template: None,
            body_template: "This template will be deleted.".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        // Delete template
        {
            let mut template_manager = service.template_manager.write().await;
            let result = template_manager.delete_template("delete_test");
            assert!(result.is_ok());
        }

        // Verify deletion
        let deleted = service.get_template("delete_test").await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_template_preview_rendering() {
        let service = NotificationService::new().unwrap();

        // Register a test template
        let template = NotificationTemplate {
            id: "preview_test".to_string(),
            name: "Preview Test Template".to_string(),
            description: Some("A template for testing preview rendering".to_string()),
            subject_template: Some("Scan Results for {{contract_name}}".to_string()),
            body_template: "Hello {{user_name}},\n\nYour scan of {{contract_name}} found {{vuln_count}} vulnerabilities.\n\nSeverity: {{severity}}.".to_string(),
            supported_channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            default_priority: NotificationPriority::High,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: Some("User name".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "contract_name".to_string(),
                    description: Some("Contract name".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "vuln_count".to_string(),
                    description: Some("Vulnerability count".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::Number,
                },
                TemplateVariable {
                    name: "severity".to_string(),
                    description: Some("Severity level".to_string()),
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        // Build context
        let mut context = TemplateContext::new();
        context.insert("user_name".to_string(), "Alice".to_string());
        context.insert("contract_name".to_string(), "TokenContract".to_string());
        context.insert("vuln_count".to_string(), "5".to_string());
        context.insert("severity".to_string(), "Critical".to_string());

        // Render preview
        let result = service
            .render_preview("preview_test", context)
            .await;

        assert!(result.is_ok());
        let preview = result.unwrap();

        // Verify rendered output
        assert_eq!(preview.template_id, "preview_test");
        assert_eq!(preview.template_name, "Preview Test Template");
        assert!(preview.subject.is_some());
        assert!(preview.subject.unwrap().contains("TokenContract"));
        assert!(preview.plain_text_body.contains("Alice"));
        assert!(preview.plain_text_body.contains("TokenContract"));
        assert!(preview.plain_text_body.contains("5"));
        assert!(preview.plain_text_body.contains("Critical"));

        // Email templates should have HTML body
        assert!(preview.html_body.is_some());
        let html = preview.html_body.unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Alice"));
        assert!(html.contains("TokenContract"));
    }

    #[tokio::test]
    async fn test_template_preview_non_email_channel() {
        let service = NotificationService::new().unwrap();

        // Register an SMS-only template (no HTML needed)
        let template = NotificationTemplate {
            id: "sms_preview_test".to_string(),
            name: "SMS Preview Test".to_string(),
            description: None,
            subject_template: None,
            body_template: "{{alert_type}}: {{message}}".to_string(),
            supported_channels: vec![NotificationChannel::SMS],
            default_priority: NotificationPriority::High,
            variables: vec![
                TemplateVariable {
                    name: "alert_type".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "message".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        let mut context = TemplateContext::new();
        context.insert("alert_type".to_string(), "CRITICAL".to_string());
        context.insert("message".to_string(), "Reentrancy vulnerability detected".to_string());

        let result = service
            .render_preview("sms_preview_test", context)
            .await;

        assert!(result.is_ok());
        let preview = result.unwrap();

        // SMS-only templates should NOT have HTML body
        assert!(preview.html_body.is_none());
        assert!(preview.plain_text_body.contains("CRITICAL"));
        assert!(preview.plain_text_body.contains("Reentrancy"));
    }

    #[tokio::test]
    async fn test_template_preview_missing_variable() {
        let service = NotificationService::new().unwrap();

        let template = NotificationTemplate {
            id: "missing_var_test".to_string(),
            name: "Missing Variable Test".to_string(),
            description: None,
            subject_template: None,
            body_template: "Hello {{name}}, your scan {{scan_id}} is {{status}}.".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![
                TemplateVariable {
                    name: "name".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "scan_id".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
                TemplateVariable {
                    name: "status".to_string(),
                    description: None,
                    required: true,
                    default_value: None,
                    variable_type: VariableType::String,
                },
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        // Missing required variable "status"
        let mut context = TemplateContext::new();
        context.insert("name".to_string(), "Bob".to_string());
        context.insert("scan_id".to_string(), "scan_456".to_string());

        let result = service
            .render_preview("missing_var_test", context)
            .await;

        // Should fail due to missing required variable
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_template_info() {
        let service = NotificationService::new().unwrap();

        // Add two templates
        let template1 = NotificationTemplate {
            id: "info_test_1".to_string(),
            name: "Info Test 1".to_string(),
            description: Some("First test template".to_string()),
            subject_template: None,
            body_template: "Template 1 body".to_string(),
            supported_channels: vec![NotificationChannel::Email],
            default_priority: NotificationPriority::Normal,
            variables: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        let template2 = NotificationTemplate {
            id: "info_test_2".to_string(),
            name: "Info Test 2".to_string(),
            description: None,
            subject_template: None,
            body_template: "Template 2 body".to_string(),
            supported_channels: vec![NotificationChannel::SMS, NotificationChannel::InApp],
            default_priority: NotificationPriority::Low,
            variables: vec![TemplateVariable {
                name: "test_var".to_string(),
                description: Some("A test variable".to_string()),
                required: false,
                default_value: Some("default".to_string()),
                variable_type: VariableType::String,
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 2,
            active: true,
        };

        service.add_template(template1).await.unwrap();
        service.add_template(template2).await.unwrap();

        let info_list = service.list_template_info().await;
        assert_eq!(info_list.len(), 2);

        let info1 = info_list.iter().find(|t| t.id == "info_test_1").unwrap();
        assert_eq!(info1.name, "Info Test 1");
        assert_eq!(info1.description, Some("First test template".to_string()));
        assert_eq!(info1.version, 1);

        let info2 = info_list.iter().find(|t| t.id == "info_test_2").unwrap();
        assert_eq!(info2.name, "Info Test 2");
        assert_eq!(info2.supported_channels.len(), 2);
        assert_eq!(info2.variables.len(), 1);
        assert_eq!(info2.variables[0].name, "test_var");
        assert_eq!(info2.version, 2);
    }

    #[tokio::test]
    async fn test_template_preview_not_found() {
        let service = NotificationService::new().unwrap();

        let context = TemplateContext::new();
        let result = service
            .render_preview("nonexistent_template", context)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_template_preview_in_app_only() {
        let service = NotificationService::new().unwrap();

        let template = NotificationTemplate {
            id: "inapp_preview".to_string(),
            name: "In-App Only".to_string(),
            description: None,
            subject_template: Some("New Alert".to_string()),
            body_template: "You have {{count}} new alerts.".to_string(),
            supported_channels: vec![NotificationChannel::InApp],
            default_priority: NotificationPriority::Normal,
            variables: vec![TemplateVariable {
                name: "count".to_string(),
                description: None,
                required: true,
                default_value: None,
                variable_type: VariableType::Number,
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            active: true,
        };

        service.add_template(template).await.unwrap();

        let mut context = TemplateContext::new();
        context.insert("count".to_string(), "3".to_string());

        let result = service
            .render_preview("inapp_preview", context)
            .await;

        assert!(result.is_ok());
        let preview = result.unwrap();
        assert!(preview.plain_text_body.contains("3"));
        // In-app only templates should not have HTML body
        assert!(preview.html_body.is_none());
    }
}
