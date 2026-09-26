package proxy

// lastEventBoundary returns the index just past the last blank line in
// data, or -1 if there is none. Per the WHATWG event-stream grammar a line
// ends with CRLF, LF or CR, and an empty line ends an event. A CR as the
// very last byte may be the first half of a CRLF still in flight, so it
// only ends a line at EOF.
func lastEventBoundary(data []byte, atEOF bool) int {
	boundary := -1
	lineStart := 0
	for index := 0; index < len(data); index++ {
		var terminatorLength int
		switch data[index] {
		case '\n':
			terminatorLength = 1
		case '\r':
			switch {
			case index+1 < len(data) && data[index+1] == '\n':
				terminatorLength = 2
			case index+1 == len(data) && !atEOF:
				return boundary
			default:
				terminatorLength = 1
			}
		default:
			continue
		}
		lineEnd := index + terminatorLength
		if index == lineStart {
			boundary = lineEnd
		}
		lineStart = lineEnd
		index = lineEnd - 1
	}
	return boundary
}
