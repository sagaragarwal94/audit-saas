const isTTY = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;

const CODES = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  orange: "\x1b[38;5;208m",
  blue: "\x1b[34m",
  gray: "\x1b[90m",
  cyan: "\x1b[36m"
};

function paint(code, text) {
  return isTTY ? `${code}${text}${CODES.reset}` : text;
}

export const color = {
  bold: (text) => paint(CODES.bold, text),
  dim: (text) => paint(CODES.dim, text),
  red: (text) => paint(CODES.red, text),
  green: (text) => paint(CODES.green, text),
  yellow: (text) => paint(CODES.yellow, text),
  orange: (text) => paint(CODES.orange, text),
  blue: (text) => paint(CODES.blue, text),
  gray: (text) => paint(CODES.gray, text),
  cyan: (text) => paint(CODES.cyan, text)
};

const SEVERITY_COLOR = {
  critical: color.red,
  high: color.orange,
  medium: color.yellow,
  low: color.blue,
  info: color.gray
};

export function severityLabel(severity, count) {
  return severityColor(severity, `${count} ${severity}`);
}

export function severityColor(severity, text) {
  const paintFn = SEVERITY_COLOR[severity] || color.gray;
  return paintFn(text);
}

export function formatDuration(ms) {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

export function padRight(value, width) {
  const str = String(value);
  return str.length >= width ? str : str + " ".repeat(width - str.length);
}
