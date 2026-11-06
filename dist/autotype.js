export function parseAutotype(template, fields) {
    if (!template.trim())
        throw new Error("Autotype template is empty");
    const steps = [];
    for (const token of template.match(/\{[^}]+\}|[^{]+/g) ?? []) {
        const key = token.startsWith("{") && token.endsWith("}") ? token.slice(1, -1).toLowerCase() : "";
        if (!key) {
            steps.push({ kind: "text", value: token });
            continue;
        }
        if (key === "tab" || key === "enter") {
            steps.push({ kind: "key", value: key });
            continue;
        }
        const value = fields[key];
        if (value === undefined)
            throw new Error(`Unknown autotype field: ${key}`);
        steps.push({ kind: "text", value });
    }
    return steps;
}
export function autotypePreview(steps) {
    return steps.map(s => s.kind === "text" ? s.value : `[${s.value.toUpperCase()}]`).join("");
}
