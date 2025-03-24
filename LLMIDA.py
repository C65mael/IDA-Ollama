import functools
import idaapi
import ida_kernwin
import idc
import idautils
import threading
import ollama
import ida_hexrays
import json
import re

# =============================================================================
# Main Plugin Class: Pseudocode Analysis, Variable Renaming, and Function Renaming
# =============================================================================

class ChatPlugin(idaapi.plugin_t):
    flags = 0
    # Pseudocode analysis action
    action_name = "chat:analyze_pseudocode"
    menu_path = "Edit/chat/Analyze Pseudocode"
    # Variable renaming action
    rename_action_name = "chat:rename_variables"
    rename_menu_path = "Edit/chat/Rename Variables"
    # Function renaming action
    function_rename_action_name = "chat:rename_function"
    function_rename_menu_path = "Edit/chat/Rename Function"

    wanted_name = 'Pseudocode Analyzer'
    wanted_hotkey = ''
    comment = "Use AI to analyze decompiled pseudocode, rename variables and rename functions"
    help = "Requires Hex-Rays decompiler"
    menu = None

    def init(self):
        # Register pseudocode analysis action
        action_desc = idaapi.action_desc_t(
            self.action_name,
            'Analyze Pseudocode',
            PseudocodeHandler(),
            "Ctrl+Alt+P",
            'Send pseudocode to AI for analysis',
            199
        )
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(self.menu_path, self.action_name, idaapi.SETMENU_APP)

        # Register variable renaming action
        rename_action_desc = idaapi.action_desc_t(
            self.rename_action_name,
            'Rename Variables',
            RenameHandler(),
            "Ctrl+Alt+R",
            'Send function code to AI for variable renaming suggestions',
            199
        )
        idaapi.register_action(rename_action_desc)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Register function renaming action
        function_rename_desc = idaapi.action_desc_t(
            self.function_rename_action_name,
            'Rename Function',
            FunctionRenameHandler(),
            "Ctrl+Alt+F",
            'Send function code to AI for function renaming suggestions',
            199
        )
        idaapi.register_action(function_rename_desc)
        idaapi.attach_action_to_menu(self.function_rename_menu_path, self.function_rename_action_name, idaapi.SETMENU_APP)

        # Register right-click menu hook
        self.menu = ChatContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.menu_path, self.action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.function_rename_menu_path, self.function_rename_action_name)
        if self.menu:
            self.menu.unhook()

# -----------------------------------------------------------------------------
# Right-click menu hook: Add functionality in the pseudocode view
# -----------------------------------------------------------------------------

class ChatContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        widget_type = idaapi.get_widget_type(form)
        if widget_type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, ChatPlugin.action_name, "Chat/Analyze_Pseudocode")
            idaapi.attach_action_to_popup(form, popup, ChatPlugin.rename_action_name, "Chat/Rename_Variables")
            idaapi.attach_action_to_popup(form, popup, ChatPlugin.function_rename_action_name, "Chat/Rename_Function")

# -----------------------------------------------------------------------------
# Pseudocode analysis function
# -----------------------------------------------------------------------------

class PseudocodeHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        code = get_pseudocode()
        if code:
            prompt = f"\n{code}\nPlease analyze the code and summarize its functionality and principles."
            query_model_async(prompt, response_handler)
        else:
            print("Error: No pseudocode available")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def get_pseudocode():
    """Get the pseudocode of the current decompilation window"""
    try:
        widget = idaapi.get_current_widget()
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu and vu.cfunc:
            return "\n".join([item.line for item in vu.cfunc.get_pseudocode()])
        viewer = idaapi.get_current_viewer()
        return "\n".join(
            idaapi.get_custom_viewer_curline(viewer, i)
            for i in range(idaapi.get_line_qty(viewer))
        )
    except Exception as e:
        print(f"Pseudocode fetch failed: {str(e)}")
        return None

def response_handler(response):
    """Display the AI's pseudocode analysis results"""
    content = response.get('message', {}).get('content', 'No analysis available')
    title = "AI Analysis Result"
    viewer = idaapi.simplecustviewer_t()
    if viewer.Create(title):
        viewer.ClearLines()
        for line in content.splitlines():
            viewer.AddLine(line.rstrip())
        viewer.Show()
    else:
        print("Failed to create result window")

# -----------------------------------------------------------------------------
# Variable renaming function
# -----------------------------------------------------------------------------

def rename_callback(address, view, response):
    """Parse the AI response and rename variables"""
    content = response.get('message', {}).get('content', '')
    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines)

    if not content.strip():
        print("The content returned by AI is empty, unable to parse JSON")
        return

    try:
        names = json.loads(content)
    except Exception as e:
        print(f"JSON parsing error: {str(e)}. Response content: {content}")
        return

    func = idaapi.get_func(address)
    if not func:
        print("Failed to get function information")
        return
    function_addr = func.start_ea

    replaced = []
    for old_name, new_name in names.items():
        if idaapi.IDA_SDK_VERSION < 760:
            lvars = {lvar.name: lvar for lvar in view.cfunc.lvars}
            if old_name in lvars and view.rename_lvar(lvars[old_name], new_name, True):
                replaced.append(old_name)
        else:
            if ida_hexrays.rename_lvar(function_addr, old_name, new_name):
                replaced.append(old_name)

    comment = idc.get_func_cmt(address, 0)
    if comment and replaced:
        for old_name in replaced:
            comment = re.sub(r'\b%s\b' % re.escape(old_name), names[old_name], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
    print(f"AI query finished! {len(replaced)} variable(s) renamed.")

class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        address = idaapi.get_screen_ea()
        try:
            decompiler_output = ida_hexrays.decompile(address)
        except Exception as e:
            print(f"Decompilation failed: {str(e)}")
            return 0
        view = ida_hexrays.get_widget_vdui(ctx.widget)
        prompt = (
            f"Analyze the following code function:\n{decompiler_output}\n"
            "According to the context and suggest better variable names, reply with a JSON dictionary where keys are the original variable names and "
            "values are the proposed names. Do not explain anything, only output the JSON dictionary."
        )
        query_model_async(prompt, functools.partial(rename_callback, address, view))
        print("Request to AI for renaming variables sent...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------
# Function renaming function
# -----------------------------------------------------------------------------

def function_rename_callback(address, response):
    """Parse the AI response and rename the function"""
    content = response.get('message', {}).get('content', '')
    if not content.strip():
        print("The content returned by AI is empty, unable to rename function")
        return

    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    # Clean up the function name, keeping only the identifier part (remove parameter list, etc.)
    new_name = re.sub(r'\s*\(.*\)', '', content).strip()  # Remove parentheses and parameters
    if not new_name:
        print("AI did not provide a valid function name")
        return

    # Check if it is a valid identifier
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name):
        print(f"Function name '{new_name}' contains invalid characters and cannot be used")
        return

    if idaapi.set_name(address, new_name, idaapi.SN_CHECK):
        print(f"Function renamed to: {new_name}")
        # Try to get the current pseudocode view and refresh it
        widget = idaapi.get_current_widget()
        if widget and idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
            vdui = ida_hexrays.get_widget_vdui(widget)
            if vdui:
                vdui.refresh_view(True)
            else:
                print("Failed to get the current pseudocode VDU for refresh.")
        else:
            print("No pseudocode view is currently open, unable to refresh.")
    else:
        print(f"Failed to rename function to: {new_name}. Possible reasons: name conflict or invalid characters")

class FunctionRenameHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        current_address = idaapi.get_screen_ea()
        func = idaapi.get_func(current_address)
        if func:
            function_address_to_rename = func.start_ea
            try:
                decompiler_output = ida_hexrays.decompile(function_address_to_rename)
            except Exception as e:
                print(f"Decompilation failed: {str(e)}")
                return 0
            prompt = (
                f"Analyze this code function:\n{decompiler_output}\n"
                "Suggest a descriptive function name based on its overall behavior. Reply with a single string or relatively simple name, "
                "do not include parameters or special characters (e.g., 'processFileName' instead of 'processFileName(int id)')."
            )
            query_model_async(prompt, functools.partial(function_rename_callback, function_address_to_rename))
            print("Request to AI for renaming function sent...")
        else:
            print("The current position is not within a function, unable to rename the function.")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# =============================================================================
# Ollama interaction module
# =============================================================================

def query_model(query, cb):
    try:
        print("Request...")
        response = ollama.chat(
            model='',
            messages=[{'role': 'user', 'content': query}],
            options={
                "temperature": 0.3,
                "num_beams": 5,
                "max_new_tokens": 3072,
                "top_p": 0.9,
                "repetition_penalty": 1.2
            }
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response), ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"API Error: {str(e)}")

def query_model_async(query, cb):
    threading.Thread(target=query_model, args=(query, cb)).start()

# =============================================================================
# Plugin entry
# =============================================================================

def PLUGIN_ENTRY():
    return ChatPlugin()