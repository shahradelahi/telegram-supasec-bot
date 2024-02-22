import { parseInline as markedParseInline } from 'marked';

export async function parseInline(input: string): Promise<string> {
  return markedParseInline(input);
}
