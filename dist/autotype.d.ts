export type AutotypeStep = {
    kind: "text" | "key";
    value: string;
};
export declare function parseAutotype(template: string, fields: Record<string, string>): AutotypeStep[];
export declare function autotypePreview(steps: AutotypeStep[]): string;
