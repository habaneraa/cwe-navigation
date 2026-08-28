/**
 * xmltodict-compatible parsing on top of fast-xml-parser.
 *
 * The original python pipeline used xmltodict.parse(), and the exported
 * JSON format inherits its exact output shape, which fast-xml-parser does
 * not reproduce natively:
 *   1. attributes get a '@' prefix and come first, in document order
 *   2. a child element appearing once maps to a value, twice to an array
 *   3. mixed content: all text fragments are concatenated and (overall)
 *      stripped, then stored under '#text' *after* the child element keys
 *   4. text-less childless elements map to None (null)
 *   5. named + numeric character entities are decoded exactly once
 *      (fast-xml-parser v5 leaves numeric entities untouched, so entity
 *      decoding is done here, single-pass, like expat does for xmltodict)
 *
 * To control all of these we parse with fast-xml-parser's `preserveOrder`
 * mode (raw document structure incl. every text fragment) and implement
 * xmltodict's `_dictify` semantics ourselves. In preserveOrder mode each
 * element is one item object: `{ [tagName]: [...children], ':@': attrs }`.
 */
import { XMLParser } from 'fast-xml-parser'

export type XmlValue = null | string | XmlDict
export interface XmlDict {
  [key: string]: XmlValue | XmlValue[]
}

interface ElementItem {
  [key: string]: unknown
}

const parser = new XMLParser({
  preserveOrder: true,
  ignoreAttributes: false,
  attributeNamePrefix: '', // attributes arrive bare; dictify adds the '@' itself
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: false,
  // entities are decoded below (single-pass) because FXP v5 does not
  // decode numeric character references
  processEntities: false,
})

/**
 * Single-pass XML entity decoding: the five predefined entities plus
 * decimal/hex character references. Single-pass (one regex, one replace)
 * so `&amp;#233;` becomes the literal `&#233;` and never `é`.
 */
const ENTITY_RE = /&(amp|lt|gt|quot|apos|#[0-9]+|#[xX][0-9a-fA-F]+);/g

function decodeEntities(s: string): string {
  return s.replace(ENTITY_RE, (whole, name: string) => {
    switch (name) {
      case 'amp':
        return '&'
      case 'lt':
        return '<'
      case 'gt':
        return '>'
      case 'quot':
        return '"'
      case 'apos':
        return "'"
    }
    if (name.startsWith('#x') || name.startsWith('#X')) {
      return String.fromCodePoint(parseInt(name.slice(2), 16))
    }
    return String.fromCodePoint(parseInt(name.slice(1), 10))
  })
}

/**
 * Python `str.strip()` equivalent. Python strips whitespace per
 * str.isspace(); JS `.trim()` differs slightly (it strips \ufeff, Python
 * doesn't; Python strips \x1c-\x1f, JS doesn't). Be precise anyway.
 */
const PY_STRIP_SET = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
  0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0x1c,
  0x1d, 0x1e, 0x1f,
])

function pyStrip(s: string): string {
  let start = 0
  let end = s.length
  while (start < end && PY_STRIP_SET.has(s.charCodeAt(start))) start++
  while (end > start && PY_STRIP_SET.has(s.charCodeAt(end - 1))) end--
  return start === 0 && end === s.length ? s : s.slice(start, end)
}

/** The tag name of a preserveOrder item ('' for pure text nodes). */
function tagNameOf(item: ElementItem): string {
  for (const k of Object.keys(item)) {
    if (k !== ':@') return k
  }
  return ''
}

/** xmltodict's dictify for one element item. */
function elementToValue(item: ElementItem): XmlValue {
  // 1. attributes, in document order, with '@' prefix
  const attrDict: Record<string, string> = {}
  const rawAttrs = item[':@'] as Record<string, string> | undefined
  if (rawAttrs) {
    for (const [k, v] of Object.entries(rawAttrs)) {
      attrDict['@' + k] = decodeEntities(String(v))
    }
  }

  // 2. child elements, merged with xmltodict's once->value / twice->array rule
  const rawChildren = item[tagNameOf(item)]
  const children = Array.isArray(rawChildren) ? (rawChildren as ElementItem[]) : []
  const childKeys: string[] = []
  const childValues: XmlValue[] = []
  for (const child of children) {
    const k = tagNameOf(child)
    // '#text' items are text nodes handled below; skipping them here also
    // guards against re-entering a string (a 1-char string indexes itself)
    if (k === '' || k === '#text' || k.startsWith('?')) continue
    childKeys.push(k)
    childValues.push(elementToValue(child))
  }
  const childDict: Record<string, XmlValue | XmlValue[]> = {}
  const arrayified = new Set<string>()
  for (let i = 0; i < childKeys.length; i++) {
    const k = childKeys[i]
    const v = childValues[i]
    if (!(k in childDict)) {
      childDict[k] = v
    } else if (!arrayified.has(k)) {
      // second occurrence: wrap the previous value (whatever it is) in a list
      childDict[k] = [childDict[k] as XmlValue, v]
      arrayified.add(k)
    } else {
      ;(childDict[k] as XmlValue[]).push(v)
    }
  }

  // 3. text: decode each fragment, concatenate, strip the whole thing
  let text = ''
  for (const child of children) {
    const t = child['#text']
    if (typeof t === 'string') text += decodeEntities(t)
  }
  text = pyStrip(text)

  const hasAttrs = Object.keys(attrDict).length > 0
  const hasChildren = childKeys.length > 0

  if (!hasChildren) {
    if (text === '') {
      return hasAttrs ? attrDict : null
    }
    if (hasAttrs) {
      return { ...attrDict, '#text': text }
    }
    return text
  }

  const result: Record<string, XmlValue | XmlValue[] | string> = { ...attrDict, ...childDict }
  if (text !== '') {
    result['#text'] = text
  }
  return result
}

/**
 * xmltodict.parse(xml) equivalent: returns `{ RootName: ... }`, with the
 * xml declaration / processing instructions dropped, like xmltodict does.
 */
export function xmltodictParse(xmlText: string): XmlDict {
  const ordered = parser.parse(xmlText) as ElementItem[]
  const result: XmlDict = {}
  for (const item of ordered) {
    const k = tagNameOf(item)
    if (k === '' || k.startsWith('?')) continue
    result[k] = elementToValue(item)
  }
  return result
}
