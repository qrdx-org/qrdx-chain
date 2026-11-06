"""
Formatter-independent source text, for tests that assert where a call sits relative to
another (e.g. "the rejection path restores state before returning").

Such tests used to search ``inspect.getsource(...)`` for exact snippets, so reformatting the
code — quote style, a call wrapped over several lines, a trailing comma — broke them without
any change in behaviour. ``source_of`` returns the source normalised (one quote style, single
spaces, no space inside parentheses, no trailing commas), and searching it normalises the
needle the same way.
"""
import inspect
import re


def normalize(text: str) -> str:
    text = text.replace("'", '"')
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r",?\s*\)", ")", text)
    return text


class NormalizedSource(str):
    def index(self, sub, *args):  # type: ignore[override]
        return super().index(normalize(sub), *args)

    def find(self, sub, *args):  # type: ignore[override]
        return super().find(normalize(sub), *args)

    def __contains__(self, sub):  # type: ignore[override]
        return super().__contains__(normalize(sub))


def source_of(obj) -> NormalizedSource:
    return NormalizedSource(normalize(inspect.getsource(obj)))
