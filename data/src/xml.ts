/** Parse CWE XML into the compact object shape used by the data generator. */
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
  attributeNamePrefix: '',
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: false,
  processEntities: false
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

/** The tag name of a preserveOrder item ('' for pure text nodes). */
function tagNameOf(item: ElementItem): string {
  for (const k of Object.keys(item)) {
    if (k !== ':@') return k
  }
  return ''
}

function elementToValue(item: ElementItem): XmlValue {
  const attrDict: Record<string, string> = {}
  const rawAttrs = item[':@'] as Record<string, string> | undefined
  if (rawAttrs) {
    for (const [k, v] of Object.entries(rawAttrs)) {
      attrDict['@' + k] = decodeEntities(String(v))
    }
  }

  const rawChildren = item[tagNameOf(item)]
  const children = Array.isArray(rawChildren) ? (rawChildren as ElementItem[]) : []
  const childKeys: string[] = []
  const childValues: XmlValue[] = []
  for (const child of children) {
    const k = tagNameOf(child)
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
      childDict[k] = [childDict[k] as XmlValue, v]
      arrayified.add(k)
    } else {
      ;(childDict[k] as XmlValue[]).push(v)
    }
  }

  let text = ''
  for (const child of children) {
    const t = child['#text']
    if (typeof t === 'string') text += decodeEntities(t)
  }
  text = text.trim()

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

export function parseXml(xmlText: string): XmlDict {
  const ordered = parser.parse(xmlText) as ElementItem[]
  const result: XmlDict = {}
  for (const item of ordered) {
    const k = tagNameOf(item)
    if (k === '' || k.startsWith('?')) continue
    result[k] = elementToValue(item)
  }
  return result
}
