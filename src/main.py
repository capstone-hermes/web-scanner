import sys
from utils import process_url

if __name__ == "__main__":
    ac = len(sys.argv)
    av = sys.argv
    if ac < 2 or ac > 2 or av[1] == "-h" or av[1] == "--help":
        print("Usage: python main.py <url>")
        sys.exit(1)
    url = av[1]
    process_url(url)
