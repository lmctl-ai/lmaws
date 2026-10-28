#!/usr/bin/env python3
"""Offline regression checks for gallery artifact provenance and diagnostics."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gallery_artifacts',ROOT/'scripts/test-gallery.py')
gallery=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gallery)

class Artifacts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='lmaws-gallery-artifacts-')
        self.work=Path(self.temp.name)
        (self.work/'images').mkdir();(self.work/'data').mkdir()
    def tearDown(self): self.temp.cleanup()
    def png(self,name): (self.work/'images'/f'{name}.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
    def test_chart_input_is_not_registry_evidence(self):
        self.png('provision_job')
        (self.work/'data/provision-stages.dat').write_text('requested 1\ncreated 1\n')
        payload,error=gallery.inspect_outputs(self.work,'provision_job')
        self.assertIsNone(payload)
        self.assertIn('data/provision_job.count',error)
        self.assertIn('from lmfiles',error)
        self.assertIn(str(self.work),error)
    def test_registry_count_and_empty_registry(self):
        self.png('provision_job')
        count=self.work/'data/provision_job.count';count.write_text('1\n')
        self.assertEqual(gallery.inspect_outputs(self.work,'provision_job'),(b'1\n',None))
        count.write_text('0\n')
        payload,error=gallery.inspect_outputs(self.work,'provision_job')
        self.assertIsNone(payload)
        self.assertIn('invalid host-generated data artifact',error)
        self.assertIn('from lmfiles',error)
    def test_existing_csv_count_and_spend_contracts(self):
        self.png('inventory')
        payload,error=gallery.inspect_outputs(self.work,'inventory')
        self.assertIsNone(payload)
        self.assertIn('data/inventory.csv from lmaws',error)
        self.assertIn('data/inventory.count from lmaws',error)
        count=self.work/'data/inventory.count';count.write_text('0\n')
        self.assertEqual(gallery.inspect_outputs(self.work,'inventory'),(b'0\n',None))
        chart=self.work/'data/inventory/topic_chart.csv';chart.parent.mkdir();chart.write_text('topic,value\nfixture,1\n')
        self.assertEqual(gallery.inspect_outputs(self.work,'inventory'),(chart.read_bytes(),None))
        csv=self.work/'data/inventory.csv';csv.write_text('name\nfixture\n')
        self.assertEqual(gallery.inspect_outputs(self.work,'inventory'),(csv.read_bytes(),None))
    def test_missing_png_identifies_plot_host(self):
        payload,error=gallery.inspect_outputs(self.work,'provision_job')
        self.assertIsNone(payload)
        self.assertIn('images/provision_job.png from lmplot',error)

if __name__=='__main__':unittest.main()
