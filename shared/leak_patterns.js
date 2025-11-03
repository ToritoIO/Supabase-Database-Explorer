// Common API key patterns gathered from public breach tooling references.
// Each entry uses a fairly strict regex to cut down on false positives.
export const SPECIFIC_PATTERNS = {
  "OpenAI API Key": "sk-[A-Za-z0-9]{32,48}",
  "Stripe Secret Key": "sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted Key": "rk_live_[0-9a-zA-Z]{24}",
  "Stripe Publishable Key": "pk_live_[0-9a-zA-Z]{24}",
  "GitHub Personal Access Token": "gh[pousr]_[A-Za-z0-9]{36}",
  "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "SendGrid API Key": "SG\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]{27}",
  "Slack Token": "xox[baprs]-[A-Za-z0-9-]{10,48}",
  "Discord Bot Token": "[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Heroku API Key": "(?:[a-f0-9]{8}-){3}[a-f0-9]{8}",
};

export const GENERIC_PATTERNS = {
  "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
};

export const AWS_PATTERNS = {
  "AWS Access Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
};

export const DEFAULT_DENY_LIST = [
  "AIDAAAAAAAAAAAAAAAAA",
  "A3TAAEAAAAAAAAAAAAAA", // Common in base64 font data
  "ASIATESTAAAAAAAAAAAA",
  "AKIATESTTESTTESTTEST",
];

export const DEFAULT_PATTERN_GROUPS = {
  specifics: SPECIFIC_PATTERNS,
  generics: GENERIC_PATTERNS,
  aws: AWS_PATTERNS,
};
