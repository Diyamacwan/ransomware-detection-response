import math
from collections import Counter
from pathlib import Path


class EntropyCalculator:
    """
    Calculate Shannon entropy for file contents.

    Entropy ranges from approximately 0 to 8 bits per byte
    for byte data.

    Lower values generally indicate more repetitive/predictable
    content, while higher values indicate more random-looking
    content.
    """

    def __init__(self, max_bytes=1024 * 1024):
        # Read at most 1 MB from a file.
        self.max_bytes = max_bytes

    def calculate(self, file_path):
        """
        Calculate Shannon entropy of a file.

        Returns:
            float: entropy value between 0 and 8.
        """

        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return 0.0

        try:
            with path.open("rb") as file:
                data = file.read(self.max_bytes)

        except OSError:
            return 0.0

        if not data:
            return 0.0

        byte_counts = Counter(data)
        data_length = len(data)

        entropy = 0.0

        for count in byte_counts.values():
            probability = count / data_length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)