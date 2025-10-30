import os
from typing import Optional, Tuple
from dotenv import load_dotenv

# Load .env in this folder if present
ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(ENV_PATH):
    load_dotenv(ENV_PATH)
else:
    load_dotenv()


def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(key, default)


def get_gemini_settings() -> Tuple[Optional[str], str]:
    api_key = get_env("GEMINI_API_KEY") or get_env("GOOGLE_API_KEY")
    model = get_env("GEMINI_MODEL", "gemini-1.5-flash")
    return api_key, model


def configure_dspy() -> str:
    """
    Try to configure DSPy to use Gemini. Returns a mode string:
    - "dspy": DSPy configured successfully with Gemini LM
    - "fallback": DSPy not available or Gemini not configured; consumer should use a direct Gemini client
    """
    api_key, model = get_gemini_settings()
    try:
        import dspy
        # Prefer google/ prefix for DSPy LM name if supported
        lm_name_candidates = [f"google/{model}", f"gemini/{model}", model]
        configured = False
        last_err = None
        for lm_name in lm_name_candidates:
            try:
                dspy.configure(lm=dspy.LM(model=lm_name, api_key=api_key), temperature=float(get_env("LM_TEMPERATURE", "0.2")))
                configured = True
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
                continue
        if not configured:
            if os.getenv("DEBUG_DSPY_SETUP") == "1":
                print(f"[WARN] DSPy Gemini LM configuration failed: {last_err}")
            return "fallback"
        return "dspy"
    except Exception as e:  # noqa: BLE001
        if os.getenv("DEBUG_DSPY_SETUP") == "1":
            print(f"[WARN] DSPy not available or config failed: {e}")
        return "fallback"
