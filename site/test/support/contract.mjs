// The WebMCP contract for stoop's tools. It is checked against what the browser registered
// and what each tool resolved with, so it judges the shipped script itself. Limits: tool and
// parameter names at most 30 characters, tool descriptions 500, parameter descriptions 150,
// and a result at most 1500 characters once serialised. A result is an object, which the
// browser serialises once, so the length measured is the JSON text the agent receives.
// Descriptions are positive ("Returns ..."), and every tool states its three annotations.
export const LIMITS = { name: 30, parameter: 30, description: 500, parameterDescription: 150, output: 1500, tools: 5 };

export const ANNOTATIONS = ["readOnlyHint", "untrustedContentHint", "consequentialHint"];

const NEGATIVE = /\b(does not|do not|doesn't|don't|cannot|can't|won't|never|not|no|without|nothing)\b/i;

export function contractProblems(tools, outputs = {}) {
  const problems = [];
  if (tools.length < LIMITS.tools) problems.push(`only ${tools.length} tools are registered; at least ${LIMITS.tools} are required`);
  for (const tool of tools) {
    const where = String(tool.name ?? "(unnamed)");
    if (typeof tool.name !== "string" || !/^[a-z][a-z0-9_]*$/.test(tool.name)) problems.push(`${where}: the name must be lower snake case`);
    if (typeof tool.name === "string" && tool.name.length > LIMITS.name) problems.push(`${where}: the name is ${tool.name.length} characters, over ${LIMITS.name}`);

    if (typeof tool.description !== "string" || !tool.description) {
      problems.push(`${where}: the tool has no description`);
    } else {
      if (tool.description.length > LIMITS.description) problems.push(`${where}: the description is ${tool.description.length} characters, over ${LIMITS.description}`);
      if (!/^Returns\b/.test(tool.description)) problems.push(`${where}: the description must start with "Returns"`);
      if (NEGATIVE.test(tool.description)) problems.push(`${where}: the description uses negative wording`);
    }

    const annotations = tool.annotations ?? {};
    for (const key of ANNOTATIONS) {
      if (typeof annotations[key] !== "boolean") problems.push(`${where}: the annotation ${key} is not stated as true or false`);
    }
    if (annotations.readOnlyHint === true && annotations.consequentialHint === true) {
      problems.push(`${where}: a tool cannot be both read-only and consequential`);
    }

    const schema = tool.inputSchema ?? {};
    if (schema.type !== "object") problems.push(`${where}: the input schema must be an object`);
    for (const [param, definition] of Object.entries(schema.properties ?? {})) {
      if (param.length > LIMITS.parameter) problems.push(`${where}: the parameter ${param} is ${param.length} characters, over ${LIMITS.parameter}`);
      const description = definition?.description;
      if (typeof description !== "string" || !description) {
        problems.push(`${where}: the parameter ${param} has no description`);
        continue;
      }
      if (description.length > LIMITS.parameterDescription) problems.push(`${where}: the description of ${param} is ${description.length} characters, over ${LIMITS.parameterDescription}`);
      if (NEGATIVE.test(description)) problems.push(`${where}: the description of ${param} uses negative wording`);
    }

    if (Object.hasOwn(outputs, tool.name)) {
      const output = outputs[tool.name];
      if (output === null || typeof output !== "object") {
        problems.push(`${where}: the result must be an object, so the agent receives structured data and not JSON text`);
      } else {
        const size = JSON.stringify(output).length;
        if (size > LIMITS.output) problems.push(`${where}: the serialised result is ${size} characters, over ${LIMITS.output}`);
      }
    }
  }
  return problems;
}
