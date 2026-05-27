"""
vulngen/stage3_generation.py
-----------------------------
Stage 3 — LLM code generation.

Supports:
  OpenAI API  — GPT-4o, GPT-4, GPT-3.5-turbo
  vLLM        — CodeLlama-34B/7B, StarCoder-15B, DeepSeek-Coder-33B

Paper settings (Section IV-A):
  Deterministic  : T = 0
  Stochastic     : T ∈ {0.2, 0.5, 0.8, 1.0}
  Seed           : 42

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import os
import re
import time
from typing import Optional, Tuple

from loguru import logger

# Optional imports — only needed for the relevant backend
try:
    import openai
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

try:
    from vllm import LLM, SamplingParams
    _VLLM_AVAILABLE = True
except ImportError:
    _VLLM_AVAILABLE = False


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

OPENAI_MODELS = {
    "gpt-4o":        "gpt-4o-2024-05-13",
    "gpt-4":         "gpt-4-0613",
    "gpt-3.5-turbo": "gpt-3.5-turbo-0125",
}

VLLM_MODELS = {
    "codellama-34b":       "codellama/CodeLlama-34b-Instruct-hf",
    "codellama-7b":        "codellama/CodeLlama-7b-Instruct-hf",
    "starcoder-15b":       "bigcode/starcoder",
    "deepseek-coder-33b":  "deepseek-ai/deepseek-coder-33b-instruct",
}


# ---------------------------------------------------------------------------
# Code extractor
# ---------------------------------------------------------------------------

def extract_code_block(text: str, language: str) -> str:
    """
    Extract the first fenced code block from a model response.
    Falls back to the raw text if no block is found.
    """
    # Try language-specific fence first
    pattern = rf"```(?:{re.escape(language)}|{re.escape(language.lower())})\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # Generic fence
    match = re.search(r"```\n?(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class CodeGenerator:
    """
    Dispatches code-generation requests to the correct backend.

    >>> gen = CodeGenerator(seed=42)
    >>> code, meta = gen.generate("gpt-4o", prompt, "python", temperature=0.0)
    """

    _vllm_cache: dict = {}   # Cache loaded vLLM models across calls

    def __init__(self, seed: int = 42, max_tokens: int = 512):
        self.seed = seed
        self.max_tokens = max_tokens
        if _OPENAI_AVAILABLE:
            self._openai_client = openai.OpenAI(
                api_key=os.environ.get("OPENAI_API_KEY", "")
            )

    def generate(
        self,
        model: str,
        prompt: str,
        language: str,
        temperature: float = 0.0,
    ) -> Tuple[str, dict]:
        """
        Generate code for *prompt* using *model*.

        Returns
        -------
        code : str
            Extracted code block.
        meta : dict
            Model, temperature, token counts, latency.
        """
        if model in OPENAI_MODELS:
            return self._generate_openai(model, prompt, language, temperature)
        elif model in VLLM_MODELS:
            return self._generate_vllm(model, prompt, language, temperature)
        else:
            raise ValueError(
                f"Unknown model '{model}'. "
                f"Available: {list(OPENAI_MODELS) + list(VLLM_MODELS)}"
            )

    # ------------------------------------------------------------------
    # OpenAI backend
    # ------------------------------------------------------------------
    def _generate_openai(
        self,
        model: str,
        prompt: str,
        language: str,
        temperature: float,
    ) -> Tuple[str, dict]:
        if not _OPENAI_AVAILABLE:
            raise ImportError("openai package not installed. Run: pip install openai")

        model_id = OPENAI_MODELS[model]
        start = time.time()
        max_retries = 5

        for attempt in range(max_retries):
            try:
                response = self._openai_client.chat.completions.create(
                    model=model_id,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    max_tokens=self.max_tokens,
                    seed=self.seed if temperature == 0.0 else None,
                )
                raw_text = response.choices[0].message.content or ""
                code = extract_code_block(raw_text, language)
                meta = {
                    "model": model,
                    "model_id": model_id,
                    "temperature": temperature,
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "latency_s": round(time.time() - start, 3),
                }
                return code, meta

            except Exception as exc:
                wait = 2 ** attempt
                logger.warning(
                    f"OpenAI error (attempt {attempt + 1}/{max_retries}): "
                    f"{exc}. Retrying in {wait}s."
                )
                time.sleep(wait)

        raise RuntimeError(f"OpenAI generation failed after {max_retries} retries.")

    # ------------------------------------------------------------------
    # vLLM backend
    # ------------------------------------------------------------------
    def _generate_vllm(
        self,
        model: str,
        prompt: str,
        language: str,
        temperature: float,
    ) -> Tuple[str, dict]:
        if not _VLLM_AVAILABLE:
            raise ImportError("vllm package not installed. Run: pip install vllm")

        model_path = VLLM_MODELS[model]
        if model_path not in self._vllm_cache:
            logger.info(f"Loading vLLM model: {model_path}")
            self._vllm_cache[model_path] = LLM(
                model=model_path,
                tensor_parallel_size=4,    # 4× A100 80GB as in the paper
                seed=self.seed,
            )

        llm = self._vllm_cache[model_path]
        sampling = SamplingParams(
            temperature=temperature,
            max_tokens=self.max_tokens,
            seed=self.seed if temperature == 0.0 else None,
        )

        start = time.time()
        outputs = llm.generate([prompt], sampling)
        raw_text = outputs[0].outputs[0].text
        code = extract_code_block(raw_text, language)

        meta = {
            "model": model,
            "model_path": model_path,
            "temperature": temperature,
            "completion_tokens": len(outputs[0].outputs[0].token_ids),
            "latency_s": round(time.time() - start, 3),
        }
        return code, meta
