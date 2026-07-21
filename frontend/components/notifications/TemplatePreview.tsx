'use client';

import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { cn } from '../../lib/notifications/utils';

// --- Types ---

interface TemplateVariable {
  name: string;
  description?: string;
  required: boolean;
  default_value?: string;
  variable_type:
    | 'String'
    | 'Number'
    | 'Email'
    | 'Phone'
    | 'Url'
    | 'Datetime'
    | 'Boolean'
    | 'Custom';
}

interface TemplateInfo {
  id: string;
  name: string;
  description?: string;
  supported_channels: string[];
  variables: TemplateVariable[];
  version: number;
  active: boolean;
  created_at: string;
  updated_at: string;
}

interface RenderedPreview {
  subject?: string;
  plain_text_body: string;
  html_body?: string;
  template_id: string;
  template_name: string;
}

type TemplateContext = Record<string, string>;

// --- Placeholder syntax highlighting ---

const PLACEHOLDER_REGEX = /\{\{(.+?)\}\}/g;

function highlightPlaceholders(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = PLACEHOLDER_REGEX.exec(text)) !== null) {
    // Add text before placeholder
    if (match.index > lastIndex) {
      parts.push(<span key={`txt-${lastIndex}`}>{text.slice(lastIndex, match.index)}</span>);
    }
    // Add highlighted placeholder
    parts.push(
      <span
        key={`ph-${match.index}`}
        className="bg-yellow-100 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-200 px-1 rounded font-mono text-xs border border-yellow-300 dark:border-yellow-700"
        title={`Variable: ${match[1].trim()}`}
      >
        {match[0]}
      </span>
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push(<span key={`txt-${lastIndex}`}>{text.slice(lastIndex)}</span>);
  }

  return parts;
}

// --- JSON Editor with variable highlighting ---

interface JsonContextEditorProps {
  variables: TemplateVariable[];
  context: TemplateContext;
  onChange: (context: TemplateContext) => void;
  errors: Record<string, string>;
}

const JsonContextEditor: React.FC<JsonContextEditorProps> = ({
  variables,
  context,
  onChange,
  errors,
}) => {
  // Use a JSON-text based editor rather than individual fields for power users
  const [jsonText, setJsonText] = useState(() => JSON.stringify(context, null, 2));
  const [parseError, setParseError] = useState<string | null>(null);

  useEffect(() => {
    // Sync external context changes into editor
    setJsonText(JSON.stringify(context, null, 2));
  }, [context]);

  const handleJsonChange = useCallback(
    (newText: string) => {
      setJsonText(newText);
      try {
        const parsed = JSON.parse(newText);
        if (typeof parsed === 'object' && !Array.isArray(parsed)) {
          const stringified: TemplateContext = {};
          for (const [key, value] of Object.entries(parsed)) {
            stringified[key] = String(value);
          }
          onChange(stringified);
          setParseError(null);
        } else {
          setParseError('Context must be a JSON object (key-value pairs)');
        }
      } catch (e) {
        setParseError((e as Error).message);
      }
    },
    [onChange]
  );

  // Fill missing required variables with defaults
  const fillMissing = useCallback(() => {
    const updated = { ...context };
    for (const v of variables) {
      if (!(v.name in updated)) {
        updated[v.name] = v.default_value || exampleValue(v);
      }
    }
    onChange(updated);
  }, [variables, context, onChange]);

  const clearAll = useCallback(() => {
    onChange({});
  }, [onChange]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
          Context (JSON)
        </label>
        <div className="flex items-center gap-2">
          <button
            onClick={fillMissing}
            className="text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors"
            title="Fill all required variables with default or example values"
          >
            Fill defaults
          </button>
          <span className="text-gray-300 dark:text-gray-600">|</span>
          <button
            onClick={clearAll}
            className="text-xs text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="relative">
        <textarea
          value={jsonText}
          onChange={e => handleJsonChange(e.target.value)}
          rows={Math.max(8, Object.keys(context).length + 3)}
          className={cn(
            'w-full px-4 py-3 font-mono text-sm border rounded-lg transition-all duration-200',
            'bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100',
            'focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none',
            'resize-y min-h-[120px]',
            parseError && 'border-red-400 focus:ring-red-500 focus:border-red-500'
          )}
          placeholder='{\n  "user_name": "Alice",\n  "contract_name": "MyContract",\n  "severity": "Critical"\n}'
          spellCheck={false}
        />
        {parseError && (
          <p className="text-xs text-red-600 dark:text-red-400 mt-1 flex items-center gap-1">
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
            {parseError}
          </p>
        )}
      </div>

      {/* Variable errors */}
      {Object.keys(errors).length > 0 && (
        <div className="space-y-1">
          {Object.entries(errors).map(([varName, errMsg]) => (
            <p
              key={varName}
              className="text-xs text-orange-600 dark:text-orange-400 flex items-center gap-1"
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path
                  fillRule="evenodd"
                  d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                  clipRule="evenodd"
                />
              </svg>
              <strong>{varName}:</strong> {errMsg}
            </p>
          ))}
        </div>
      )}

      {/* Variable reference sidebar */}
      <details className="group">
        <summary className="text-xs text-gray-500 dark:text-gray-400 cursor-pointer hover:text-gray-700 dark:hover:text-gray-200 transition-colors select-none">
          Available variables ({variables.length})
        </summary>
        <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-1.5">
          {variables.map(v => (
            <div
              key={v.name}
              className={cn(
                'flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs',
                'bg-gray-100 dark:bg-gray-800 border',
                v.name in context
                  ? 'border-green-300 dark:border-green-700'
                  : 'border-gray-200 dark:border-gray-700'
              )}
              title={v.description || v.name}
            >
              <span
                className={cn(
                  'w-1.5 h-1.5 rounded-full flex-shrink-0',
                  v.name in context ? 'bg-green-500' : 'bg-gray-400'
                )}
              />
              <code className="font-mono text-gray-800 dark:text-gray-200">{v.name}</code>
              {v.required && (
                <span className="text-red-500 dark:text-red-400 ml-auto text-[10px] font-semibold">
                  required
                </span>
              )}
              <span className="text-gray-400 text-[10px]">{v.variable_type}</span>
            </div>
          ))}
        </div>
      </details>
    </div>
  );
};

// --- Preview Panels ---

function SubjectPreview({ subject }: { subject?: string }) {
  if (!subject) return null;
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Subject Line</h4>
      <div className="p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
        <p className="text-base font-medium text-gray-900 dark:text-gray-100">
          {highlightPlaceholders(subject)}
        </p>
      </div>
    </div>
  );
}

function PlainTextPreview({ body }: { body: string }) {
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Plain Text</h4>
      <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
        <pre className="text-sm text-gray-800 dark:text-gray-200 whitespace-pre-wrap font-sans leading-relaxed">
          {highlightPlaceholders(body)}
        </pre>
      </div>
    </div>
  );
}

function HtmlPreview({ html }: { html: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300">HTML Preview</h4>
        <span className="text-[10px] text-gray-400 font-mono">iframe sandbox</span>
      </div>
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white">
        <iframe
          srcDoc={html}
          title="Email template preview"
          className="w-full min-h-[300px] border-0"
          sandbox="allow-same-origin"
        />
      </div>
    </div>
  );
}

// --- Main Component ---

export interface TemplatePreviewProps {
  templates: TemplateInfo[];
  onPreview: (templateId: string, context: TemplateContext) => Promise<RenderedPreview>;
  onFetchTemplates?: () => Promise<TemplateInfo[]>;
  isLoading?: boolean;
}

export const TemplatePreview: React.FC<TemplatePreviewProps> = ({
  templates,
  onPreview,
  onFetchTemplates,
  isLoading: externalLoading = false,
}) => {
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [context, setContext] = useState<TemplateContext>({});
  const [renderedPreview, setRenderedPreview] = useState<RenderedPreview | null>(null);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'plain' | 'html'>('plain');
  const [configCopied, setConfigCopied] = useState(false);

  const selectedTemplate = useMemo(
    () => templates.find(t => t.id === selectedTemplateId),
    [templates, selectedTemplateId]
  );

  // Auto-populate context with defaults when template changes
  useEffect(() => {
    if (selectedTemplate) {
      const defaults: TemplateContext = {};
      for (const v of selectedTemplate.variables) {
        if (v.default_value) {
          defaults[v.name] = v.default_value;
        }
      }
      setContext(defaults);
      setRenderedPreview(null);
      setPreviewError(null);
    }
  }, [selectedTemplateId]);

  // Validate context
  const validationErrors = useMemo(() => {
    const errors: Record<string, string> = {};
    if (!selectedTemplate) return errors;
    for (const v of selectedTemplate.variables) {
      if (v.required && !(v.name in context) && !context[v.name]) {
        errors[v.name] = 'Required variable is missing';
      }
    }
    return errors;
  }, [selectedTemplate, context]);

  const handlePreview = useCallback(async () => {
    if (!selectedTemplateId || !onPreview) return;
    setIsPreviewing(true);
    setPreviewError(null);
    try {
      const result = await onPreview(selectedTemplateId, context);
      setRenderedPreview(result);
      // Auto-select HTML tab if available
      if (result.html_body) {
        setActiveTab('html');
      }
    } catch (e) {
      setPreviewError(e instanceof Error ? e.message : 'Preview failed');
      setRenderedPreview(null);
    } finally {
      setIsPreviewing(false);
    }
  }, [selectedTemplateId, context, onPreview]);

  const handleCopyConfig = useCallback(async () => {
    if (!selectedTemplateId) return;
    const config = {
      template_id: selectedTemplateId,
      context,
    };
    try {
      await navigator.clipboard.writeText(JSON.stringify(config, null, 2));
      setConfigCopied(true);
      setTimeout(() => setConfigCopied(false), 2000);
    } catch {
      // Fallback
    }
  }, [selectedTemplateId, context]);

  const hasHtml = Boolean(renderedPreview?.html_body);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Template Preview</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
            Preview notification templates with sample data before sending to users
          </p>
        </div>
        {onFetchTemplates && (
          <button
            onClick={onFetchTemplates}
            disabled={externalLoading}
            className="px-3 py-1.5 text-xs font-medium text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition-colors disabled:opacity-50"
          >
            {externalLoading ? 'Refreshing...' : 'Refresh templates'}
          </button>
        )}
      </div>

      {/* Template Selector */}
      <div className="space-y-2">
        <label
          htmlFor="template-selector"
          className="block text-sm font-semibold text-gray-700 dark:text-gray-300"
        >
          Select Template
        </label>
        <select
          id="template-selector"
          value={selectedTemplateId}
          onChange={e => setSelectedTemplateId(e.target.value)}
          className={cn(
            'w-full px-4 py-2.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg',
            'bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100',
            'focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none',
            'transition-all duration-200 appearance-none cursor-pointer',
            'hover:border-gray-400 dark:hover:border-gray-500'
          )}
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3E%3Cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3E%3C/svg%3E")`,
            backgroundRepeat: 'no-repeat',
            backgroundPosition: 'right 0.75rem center',
            backgroundSize: '1.25rem',
            paddingRight: '2.5rem',
          }}
        >
          <option value="">Choose a template...</option>
          {templates.map(t => (
            <option key={t.id} value={t.id}>
              {t.name} (v{t.version}) — {t.supported_channels.join(', ')}
            </option>
          ))}
        </select>

        {selectedTemplate && (
          <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
            <span>Version {selectedTemplate.version}</span>
            <span>•</span>
            <span>{selectedTemplate.supported_channels.length} channel(s)</span>
            <span>•</span>
            <span className={cn(selectedTemplate.active ? 'text-green-600' : 'text-red-600')}>
              {selectedTemplate.active ? 'Active' : 'Inactive'}
            </span>
            {selectedTemplate.description && (
              <>
                <span>•</span>
                <span className="truncate max-w-xs">{selectedTemplate.description}</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Two-column layout: Context Editor | Preview */}
      {selectedTemplate ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left: Context Editor */}
          <div className="space-y-4">
            <JsonContextEditor
              variables={selectedTemplate.variables}
              context={context}
              onChange={setContext}
              errors={validationErrors}
            />

            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={handlePreview}
                disabled={isPreviewing || Object.keys(validationErrors).length > 0}
                className={cn(
                  'flex-1 px-4 py-2.5 text-sm font-semibold text-white rounded-lg transition-all duration-200',
                  'bg-blue-600 hover:bg-blue-700 active:bg-blue-800',
                  'disabled:opacity-40 disabled:cursor-not-allowed',
                  'focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
                  isPreviewing && 'animate-pulse'
                )}
              >
                {isPreviewing ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    Rendering...
                  </span>
                ) : (
                  'Render Preview'
                )}
              </button>

              <button
                onClick={handleCopyConfig}
                disabled={!selectedTemplateId}
                className={cn(
                  'px-4 py-2.5 text-sm font-medium rounded-lg transition-all duration-200',
                  'border border-gray-300 dark:border-gray-600',
                  'text-gray-700 dark:text-gray-300',
                  'hover:bg-gray-100 dark:hover:bg-gray-800',
                  'disabled:opacity-40 disabled:cursor-not-allowed'
                )}
                title="Copy template config as JSON"
              >
                {configCopied ? (
                  <span className="flex items-center gap-1.5 text-green-600">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                    Copied
                  </span>
                ) : (
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                    />
                  </svg>
                )}
              </button>
            </div>

            {previewError && (
              <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-700 dark:text-red-400 flex items-center gap-2">
                  <svg className="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                      clipRule="evenodd"
                    />
                  </svg>
                  {previewError}
                </p>
              </div>
            )}
          </div>

          {/* Right: Rendered Preview */}
          <div className="space-y-4">
            {renderedPreview ? (
              <>
                <SubjectPreview subject={renderedPreview.subject} />

                {hasHtml && (
                  <div className="flex items-center gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-0.5">
                    <button
                      onClick={() => setActiveTab('plain')}
                      className={cn(
                        'flex-1 py-1.5 text-xs font-medium rounded-md transition-all',
                        activeTab === 'plain'
                          ? 'bg-white dark:bg-gray-700 shadow-sm text-gray-900 dark:text-gray-100'
                          : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
                      )}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setActiveTab('html')}
                      className={cn(
                        'flex-1 py-1.5 text-xs font-medium rounded-md transition-all',
                        activeTab === 'html'
                          ? 'bg-white dark:bg-gray-700 shadow-sm text-gray-900 dark:text-gray-100'
                          : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
                      )}
                    >
                      HTML
                    </button>
                  </div>
                )}

                {activeTab === 'plain' && (
                  <PlainTextPreview body={renderedPreview.plain_text_body} />
                )}

                {activeTab === 'html' && renderedPreview.html_body && (
                  <HtmlPreview html={renderedPreview.html_body} />
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-full min-h-[300px] border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-800/50">
                <svg
                  className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.5}
                    d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                  />
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.5}
                    d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                  />
                </svg>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Select a template and click <strong>Render Preview</strong> to see the output
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-800/50">
          <svg
            className="w-14 h-14 text-gray-300 dark:text-gray-600 mb-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
            />
          </svg>
          <h4 className="text-base font-medium text-gray-700 dark:text-gray-300 mb-1">
            No Template Selected
          </h4>
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center max-w-sm">
            Choose a template from the dropdown above to preview how it renders with custom context
            data.
          </p>
        </div>
      )}
    </div>
  );
};

export default TemplatePreview;

// --- Helper ---

function exampleValue(variable: TemplateVariable): string {
  switch (variable.variable_type) {
    case 'Number':
      return '42';
    case 'Email':
      return 'user@example.com';
    case 'Phone':
      return '+1234567890';
    case 'Url':
      return 'https://example.com/report/abc123';
    case 'Datetime':
      return new Date().toISOString();
    case 'Boolean':
      return 'true';
    default:
      return `{{${variable.name}}}`;
  }
}
