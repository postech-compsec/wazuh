import os
import sys
import argparse
import json
from clang.cindex import Index, CursorKind, Config, TranslationUnit, TokenKind

MACRO_THRES = 32

def find_invoking_functions(file_path, symbols, file_args=None):
    """
    Parse the given file with libclang and return a set of function definitions
    (Cursor objects) that contain calls to any of the symbols.
    """
    print("f:", file_path)
    index = Index.create()
    try:
        tu = index.parse(
            file_path,
            args=file_args,
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )
    except Exception as e:
        sys.stderr.write(f"Failed to parse {file_path}: {e}\n")
        return set()

    matches = set()

    def is_target_call(node):
        if node.kind == CursorKind.CALL_EXPR:
            # print(node.kind, node.spelling)
            tokens = list(node.get_tokens())
            for token in tokens:
                if token.spelling in symbols:
                    return True

            referenced = node.get_definition() or node.referenced
            name = referenced.spelling if referenced else None
            if not name:
                for tok in node.get_tokens():
                    if tok.kind == TokenKind.IDENTIFIER:
                        name = tok.spelling
                        break

            if name in symbols:
                matches.add(current_func)

        # catch nested references
        if node.kind in (CursorKind.DECL_REF_EXPR,
                         CursorKind.MEMBER_REF_EXPR,
                         CursorKind.UNEXPOSED_EXPR):
            if node.spelling in symbols:
                return True

        # Recurse into children
        for child in node.get_children():
            if is_target_call(child):
                return True

        return False

    def visit(node, current_func, depth):
        width = "| " * (depth - 1)
        if current_func is None:
            print(f"{width}+{node.kind}: {node.displayname}")
        else:
            print(f"{current_func.spelling} {width}+{node.kind}: {node.displayname}")
        depth += 1

        if node.kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.FUNCTION_TEMPLATE
        ):
            # tell definitions from forward declarations
            if node.is_definition():
                current_func = node
                print(f"\n----- FUNC: {current_func.spelling} -----")

        # Detect call expressions by examining callee reference nodes
        # if node.kind == CursorKind.CALL_EXPR and current_func:
            # if is_target_call(node):
                # matches.add(current_func)

        # only look into the body of a function definition
        if current_func:
            if node.kind == CursorKind.FUNCTION_DECL:
                # case 1: node itself is a symbol (due to decl, gotta skip!)
                pass

            elif node.kind == CursorKind.CALL_EXPR:
                if node.spelling:
                    if node.spelling in symbols:
                        # case 2-1: call expr that's spelled out (e.g., assert)
                        print("found (2-1)", node.spelling)
                        matches.add(current_func)
                else:
                    # case 2-2: call expr with empty spelling
                    tokens = list(node.get_tokens())
                    if len(tokens) < MACRO_THRES: # dirty hack for skipping macros
                        for token in tokens:
                            # print(token.spelling)
                            if token.spelling in symbols:
                                print("found (2-2)", node.spelling, token.spelling)
                                matches.add(current_func)

            elif node.kind == CursorKind.UNEXPOSED_EXPR and not node.spelling:
                tokens = list(node.get_tokens())
                if len(tokens) < MACRO_THRES: # dirty hack for skipping macros
                    show = False
                    for token in tokens:
                        # print(token.spelling)
                        if token.spelling in symbols:
                            print("found (3)", node.spelling, token.spelling)
                            matches.add(current_func)

            elif node.kind == CursorKind.COMPOUND_STMT:
                tokens = list(node.get_tokens())
                for token in tokens:
                    if token.spelling in symbols:
                        print("found (4)", node.spelling, token.spelling)
                        matches.add(current_func)

        # visit all children if the node belongs to the current source file
        if node.location.file is None or node.location.file.name == file_path:
            for child in node.get_children():
                visit(child, current_func, depth)

    visit(tu.cursor, None, depth=0)
    return matches


def walk_dir(source_dir, symbols, compile_db):
    results = {}
    for root, dirs, files in os.walk(source_dir):
        for fname in files:
            if fname.lower().endswith((".c", ".cpp", ".cc", ".cxx")):
                # if fname != "secure.c":
                    # continue
                path = os.path.abspath(os.path.join(root, fname))
                if compile_db and path in compile_db:
                    file_args = compile_db.get(path)
                else:
                    file_args = None

                funcs = find_invoking_functions(path, symbols, file_args)
                if funcs:
                    results[path] = funcs

    return results


def pprint(results):
    for path, funcs in results.items():
        print(f"\nIn file: {path}")
        for fn in funcs:
            try:
                loc = fn.location
                print(f"  - {fn.spelling} (line {loc.line}, col {loc.column})")
            except:
                pass


def load_compile_commands(db_path):
    try:
        with open(db_path, "r") as f:
            entries = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Failed to load compile commands database: {e}")
        return {}

    db = {}
    for entry in entries:
        # Normalize path
        filepath = os.path.abspath(
            os.path.join(entry.get("directory", ""), entry.get("file", ""))
        )

        # Combine command or arguments
        if "arguments" in entry:
            args = entry["arguments"][1:] if entry["arguments"] else []
        else:
            cmd = entry.get("command", "")
            # Simple split; more robust parsing may be needed
            args = cmd.split()[1:]

        try:
            filtered_args = args[:args.index("-o")]
        except ValueError:
            filtered_args = args

        db[filepath] = filtered_args

    return db


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--path", required=True, help="Src directory path"
    )
    parser.add_argument(
        "-s", "--symbols", nargs="+", required=True,
        help="List of function names (symbols) to search for"
    )
    parser.add_argument(
        "--compile-db", required=False,
        help="Path to compile_commands.json file to load compile arguments"
    )
    args = parser.parse_args()

    compile_db = None
    if args.compile_db:
        compile_db = load_compile_commands(args.compile_db)
    else:
        print("Provide compile_commands.json. Run: $ bear make [options]")

    results = walk_dir(args.path, set(args.symbols), compile_db)
    if not results:
        print("No invoking functions found.")
    else:
        pprint(results)

