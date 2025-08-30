from pathlib import Path

from dyllibso.windows import get_dependencies

def test_header():
    get_dependencies(Path(r"G:\SteamLibrary\steamapps\common\Skyrim Special Edition\bink2w64.dll"))
