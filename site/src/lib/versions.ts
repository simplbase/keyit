export interface DocVersion {
  id: string;
  label: string;
  status: "current" | "in development" | "past";
  href: string;
}

export const DOC_VERSIONS: DocVersion[] = [
  { id: "v1", label: "v1", status: "current", href: "/docs" },
];

export const CURRENT_DOC_VERSION = DOC_VERSIONS[0];
