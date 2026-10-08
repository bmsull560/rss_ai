/**
 * Conservative server-side HTML sanitizer for article content rendered with
 * {@html} in Svelte components.
 *
 * Removes scriptable/embeddable elements (script, style, iframe, object,
 * embed, svg, ...), HTML comments, event handler attributes, style
 * attributes, and dangerous URL schemes (javascript:, vbscript:, data:).
 * Disallowed tags are stripped while their text content is preserved.
 *
 * Note: for spec-grade sanitization prefer DOMPurify (isomorphic-dompurify);
 * this module is a dependency-free defense-in-depth layer for untrusted RSS
 * content.
 */

const ALLOWED_TAGS = new Set([
	"a", "abbr", "b", "blockquote", "br", "caption", "code", "dd", "del",
	"details", "div", "dl", "dt", "em", "figcaption", "figure", "h1", "h2",
	"h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd", "li", "mark",
	"ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub",
	"summary", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr",
	"u", "ul", "wbr",
]);

const VOID_TAGS = new Set(["br", "hr", "img", "wbr"]);

const REMOVED_WITH_CONTENT = new Set([
	"script", "style", "iframe", "object", "embed", "noscript", "template",
	"svg", "math", "form", "base", "meta", "link",
]);

const URL_ATTRIBUTES = new Set([
	"href", "src", "action", "formaction", "poster", "background",
]);

const DANGEROUS_URL = /^\s*(?:javascript|vbscript|data)\s*:/i;

// Matches comments, closing tags, and opening tags. Quoted attribute values
// are consumed atomically so a ">" inside quotes does not end the tag early.
const TOKEN_PATTERN =
	/<!--[\s\S]*?-->|<\/?\s*([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)>/g;

const ATTR_PATTERN =
	/([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function sanitizeAttributes(attrString: string): string {
	let result = "";
	let match: RegExpExecArray | null;
	ATTR_PATTERN.lastIndex = 0;
	while ((match = ATTR_PATTERN.exec(attrString)) !== null) {
		const name = match[1].toLowerCase();
		const value = match[2] ?? match[3] ?? match[4] ?? "";

		// Drop event handlers, inline styles, and dangerous URLs
		if (name.startsWith("on")) continue;
		if (name === "style") continue;
		if (URL_ATTRIBUTES.has(name) && DANGEROUS_URL.test(value)) continue;

		const safeValue = value.replaceAll('"', """);
		result += value === "" ? ` ${name}` : ` ${name}="${safeValue}"`;
	}
	return result;
}

export function sanitizeArticleHtml(html: string): string {
	if (!html) return "";

	let result = "";
	let lastIndex = 0;
	// When set, content of a removed element is being dropped until its close tag
	let skipUntil: string | null = null;

	TOKEN_PATTERN.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = TOKEN_PATTERN.exec(html)) !== null) {
		const [token, tagNameRaw, attrString] = match;
		const tagName = (tagNameRaw ?? "").toLowerCase();
		const isClosing = token.startsWith("</");
		const isSelfClosing = /\/\s*>$/.test(token);

		if (!skipUntil) {
			result += html.slice(lastIndex, match.index);
		}
		lastIndex = match.index + token.length;

		if (skipUntil) {
			if (isClosing && tagName === skipUntil) {
				skipUntil = null;
			}
			continue;
		}

		if (token.startsWith("<!--")) continue;

		if (REMOVED_WITH_CONTENT.has(tagName)) {
			if (!isClosing && !isSelfClosing) {
				skipUntil = tagName;
			}
			continue;
		}

		// Strip disallowed tags but keep their text content
		if (!ALLOWED_TAGS.has(tagName)) continue;

		if (isClosing) {
			result += `</${tagName}>`;
		} else {
			const attrs = sanitizeAttributes(attrString ?? "");
			result += `<${tagName}${attrs}${isSelfClosing ? " /" : ""}>`;
		}
	}

	// Trailing text (dropped if a removed element was left unclosed)
	if (!skipUntil) {
		result += html.slice(lastIndex);
	}
	return result;
}
