// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How wide a PEM body line is before it wraps, in base64 characters.
///
/// RFC 7468 §2 asks for exactly 64, and every other width in the world is a
/// parser's problem rather than a writer's — but no width at all is what makes a
/// file hard to read in a terminal, so this is not optional.
pub let line_width : Int32 = 64

///|
/// Whether `unit` can appear inside base64.
///
/// Written as ASCII code units because that is what indexing a `StringView`
/// gives back, and because the alphabet is ASCII by definition — a byte outside
/// it in a PEM body is corruption, not a character.
fn is_base64(unit : UInt16) -> Bool {
  (unit >= 0x41 && unit <= 0x5A) ||
  (unit >= 0x61 && unit <= 0x7A) ||
  (unit >= 0x30 && unit <= 0x39) ||
  unit == 0x2B ||
  unit == 0x2F ||
  unit == 0x3D
}

///|
/// Wrap a DER blob as a PEM block: the `BEGIN` line, the base64 body wrapped at
/// [`line_width`], and the `END` line.
///
/// The label is written as given and appears twice, so the two lines agree —
/// RFC 7468 §3 requires that, and a reader that checks it is entitled to reject
/// the file otherwise.
pub fn armor(label : String, der : BytesView) -> String {
  let body = @base64.encode(der)
  let out = StringBuilder::StringBuilder()
  out.write_string("-----BEGIN " + label + "-----\n")
  let mut at = 0
  while at < body.length() {
    let left = body.length() - at
    let take = if left < line_width { left } else { line_width }
    out.write_string(body[at:at + take].to_owned())
    out.write_string("\n")
    at = at + take
  }
  out.write_string("-----END " + label + "-----\n")
  out.to_string()
}

///|
/// Read a PEM block: its label and the DER it wraps.
///
/// Loose in the ways a key file is loose in practice — leading text, blank lines,
/// carriage returns and trailing whitespace are all tolerated, because a key that
/// came out of an email or a Windows editor is still the same key. Strict about
/// the two things that matter: the `END` label must match the `BEGIN` label, and
/// the body must decode as base64.
pub fn dearmor(text : StringView) -> (String, Bytes) raise @asn1.Refused {
  let (label, body) = scan(text)
  let clean = strip(body)
  guard clean.length() > 0 else {
    raise @asn1.Malformed("PEM block has no body")
  }
  // Decoded strictly rather than lossily: `decode_lossy` answers an empty byte
  // string for garbage, which would turn a corrupt body into "this DER is
  // truncated" and hide where the fault actually is.
  let der = @base64.decode(clean) catch {
    _ => raise @asn1.Malformed("PEM body is not base64")
  }
  (label, der)
}

///|
/// Walk the text for a `BEGIN` line and collect the body up to the matching `END`.
fn scan(text : StringView) -> (String, StringView) raise @asn1.Refused {
  let open = "-----BEGIN "
  let close = "-----END "
  let mut at = 0
  let mut start = -1
  let mut label = ""
  while at < text.length() {
    let line = line_end(text, at)
    let body = text[at:line]
    if start < 0 {
      if starts_with(body, open) {
        let rest = body[open.length():]
        let tail = rest.length() - 5
        guard tail >= 0 && rest[tail:] == "-----" else {
          raise @asn1.Malformed("PEM begin line is malformed")
        }
        label = rest[0:tail].to_owned()
        start = line + 1
      }
    } else if starts_with(body, close) {
      let rest = body[close.length():]
      let tail = rest.length() - 5
      guard tail >= 0 && rest[tail:] == "-----" else {
        raise @asn1.Malformed("PEM end line is malformed")
      }
      // A block whose two labels disagree is two documents stitched together.
      guard rest[0:tail].to_owned() == label else {
        raise @asn1.Malformed("PEM end label does not match its begin label")
      }
      return (label, text[start:at])
    }
    at = line + 1
  }
  raise @asn1.Malformed("no PEM block found")
}

///|
/// Where the line starting at `at` ends: the index of the newline, or the length.
fn line_end(text : StringView, at : Int32) -> Int32 {
  let mut i = at
  while i < text.length() && text[i] != '\n' {
    i = i + 1
  }
  // A trailing carriage return is part of the line ending, not of the line.
  if i > at && text[i - 1] == '\r' {
    return i - 1
  }
  i
}

///|
fn starts_with(text : StringView, prefix : String) -> Bool {
  text.length() >= prefix.length() && text[0:prefix.length()] == prefix
}

///|
/// Whitespace that may appear between the characters of a body.
fn is_space(unit : UInt16) -> Bool {
  unit == 0x20 || unit == 0x09 || unit == 0x0D || unit == 0x0A
}

///|
/// The base64 characters of a PEM body and nothing else.
///
/// Whitespace between them is layout and is dropped; any other character is a
/// fault rather than something to skip, because silently discarding it is how a
/// truncated body turns into a key that parses and is wrong.
fn strip(body : StringView) -> String raise @asn1.Refused {
  let out = StringBuilder::StringBuilder()
  for i in 0..<body.length() {
    let unit = body[i]
    if is_base64(unit) {
      out.write_string(body[i:i + 1].to_owned())
    } else if !is_space(unit) {
      raise @asn1.Malformed("PEM body has a character outside base64")
    }
  }
  out.to_string()
}
