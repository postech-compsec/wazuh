import os
import sys
import argparse
from clang.cindex import Index, CursorKind, Config, TranslationUnit, TokenKind


def find_invoking_functions(file_path, symbols):
    """
    Parse the given file with libclang and return a set of function definitions
    (Cursor objects) that contain calls to any of the symbols.
    """
    print("f:", file_path)
    index = Index.create()
    try: tu = index.parse(file_path,
                options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    except Exception as e:
        sys.stderr.write(f"Failed to parse {file_path}: {e}\n")
        return set()

    matches = set()

    def is_target_call(node):
        if node.kind == CursorKind.CALL_EXPR:
            tokens = list(node.get_tokens())
            if tokens and tokens[0].spelling in symbols:
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

    depth = 0
    def visit(node, current_func, depth):
        # print(" " * depth, "+", node.kind, node.spelling)
        depth += 1

        if node.kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.FUNCTION_TEMPLATE
        ):
            current_func = node

        # Detect call expressions by examining callee reference nodes
        if node.kind == CursorKind.CALL_EXPR and current_func:
            if is_target_call(node):
                matches.add(current_func)

        # visit all children
        for child in node.get_children():
            visit(child, current_func, depth)

    visit(tu.cursor, None, depth)
    return matches


def walk_dir(source_dir, symbols):
    results = {}
    for root, dirs, files in os.walk(source_dir):
        for fname in files:
            if fname != "secure.c":
                continue
            if fname.endswith(('.c', '.cpp', '.cc', '.cxx', '.C')):
                path = os.path.join(root, fname)
                invoking = find_invoking_functions(path, symbols)
                if invoking:
                    results[path] = invoking

    return results


def pprint(results):
    for path, funcs in results.items():
        print(f"\nIn file: {path}")
        for fn in funcs:
            loc = fn.location
            print(f"  - {fn.spelling} (line {loc.line}, col {loc.column})")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--path", required=True, help="Src directory path"
    )
    parser.add_argument(
        "-s", "--symbols", nargs='+', required=True,
        help="List of function names (symbols) to search for"
    )
    args = parser.parse_args()

    results = walk_dir(args.path, set(args.symbols))
    if not results:
        print("No invoking functions found.")
    else:
        pprint(results)

