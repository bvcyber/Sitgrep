from enum import Enum


class OllamaModel(str, Enum):
    # --- Lightweight (Laptop Friendly, ~7B) ---
    QWEN3_8B = "qwen3:8b"

    # --- Mid-size (Better reasoning, 14B–16B) ---
    QWEN3_14B = "qwen3:14b"

    # --- Larger / High reasoning (Needs more RAM) ---
    QWEN3_32B = "qwen3:30b"
    QWEN3_32B = "qwen3:32b"

    # --- Massive Models ---
    QWEN3_235B = "qwen3:235b"
    QWEN3_5_CODER_NEXT = "qwen3_5-coder-next"


    @classmethod
    def toList(cls):
        return [m.value for m in OllamaModel]
