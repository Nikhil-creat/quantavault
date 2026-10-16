import os, unittest
import rag, cnn
class Core(unittest.TestCase):
    def test_rag_finds_security_doc(self):
        rag.load(os.path.join(os.path.dirname(__file__), "..", "docs"))
        self.assertTrue(rag.search("encryption passkeys audit"))
    def test_entropy_labels(self):
        self.assertEqual(cnn.scan(b"a" * 2000)["heuristic_label"], "text")
        self.assertEqual(cnn.scan(os.urandom(60000))["heuristic_label"], "encrypted_or_packed")
if __name__ == "__main__": unittest.main()
