import lldb

EXPR_TEMPLATE = """
import CryptoKit
({
    let key = unsafeBitCast(X0_HEX, to: CryptoKit.SymmetricKey.self)
    return key.withUnsafeBytes { raw -> String in
        raw.map { String(format:"%02x", $0) }.joined()
    }
})()
"""

ANSI_LINE_CLEAR_AND_CURSOR_TO_BEGGINNING = "\033[2K\r"

def _msg(msg: str) -> None:
    """Utility: print through LLDB so the message always appears."""
    print(f"{ANSI_LINE_CLEAR_AND_CURSOR_TO_BEGGINNING}[get_key] {msg}")

def gen_expr(x0_val: int) -> str:
    return EXPR_TEMPLATE.replace("X0_HEX", f"0x{x0_val:016x}")

def key_printer(frame, bp_loc, _):
    """Breakpoint callback: dump the SymmetricKey pointed to by x0."""
    reg_val = frame.FindRegister("x0").GetValueAsUnsigned()
    if not reg_val:
        print("[error] x0 is not set or invalid")
        return False

    expr = gen_expr(reg_val)
    opts = lldb.SBExpressionOptions()
    opts.SetLanguage(lldb.eLanguageTypeSwift)

    result = frame.EvaluateExpression(expr, opts)
    _msg(f"🔑 {result.GetSummary() or result.GetValue()}")

    # Also save key to ./key.bin
    key_data = (result.GetSummary() or result.GetValue()).strip("\"")
    if key_data:
        try:
            with open("key.bin", "wb") as f:
                f.write(bytes.fromhex(key_data))
            _msg("Key saved to key.bin")
        except Exception as e:
            _msg(f"[error] Failed to save key: {e}")
    else:
        _msg("[warn] No key data extracted")

    return False

SYM = (
    "$s9CryptoKit3AESO3GCMO4open_5using10Foundation4DataVAE9SealedBoxV_"
    "AA12SymmetricKeyVtKFZ"
)
OFFSET = 36  # bytes into the function (right before the bl)

def _install_bp(debugger):
    target = debugger.GetSelectedTarget()

    # Create a pending‐OK breakpoint 36 bytes into the symbol.
    cmd = f"breakpoint set --name {SYM} --address-slide {OFFSET}"
    debugger.HandleCommand(cmd)

    # Grab the breakpoint we just added (it’s always the last one).
    bp = target.GetBreakpointAtIndex(target.GetNumBreakpoints() - 1)
    if not bp.IsValid():
        print(f"[error] failed to create breakpoint for {SYM}")
        return

    bp.SetScriptCallbackFunction(__name__ + ".key_printer")
    bp.SetAutoContinue(True)
    print(f"[info] Key-extraction breakpoint installed at {SYM} + {OFFSET:#x}")

def __lldb_init_module(debugger, _dict):
    """Called automatically when `command script import` loads this file."""
    _install_bp(debugger)
