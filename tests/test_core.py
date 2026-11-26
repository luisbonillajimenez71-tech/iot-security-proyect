import unittest

from core import process
from core.metrics import evaluate, load_cases
from core.normalizer import FIELDS


class CoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.errors = process("data/sample/eve.json", "data/sample/zeek_conn.json")

    def test_esquema(self):
        self.assertEqual(len(self.events), 17)
        for event in self.events:
            self.assertEqual(set(event), set(FIELDS))

    def test_linea_danada_no_detiene(self):
        self.assertTrue(any("Línea 6" in e for e in self.errors))

    def test_escaneo(self):
        scans = [e for e in self.events if e["category"] == "Posible escaneo de puertos"]
        self.assertEqual(len(scans), 12)

    def test_metricas(self):
        result = evaluate(self.events, load_cases("data/sample/casos.csv"))
        self.assertEqual((result["VP"], result["FN"], result["FP"], result["VN"]), (4, 0, 0, 1))


if __name__ == "__main__":
    unittest.main()
