"""Small in-memory asset-book and bulletin data structures.

These are deliberately plain objects: no database, no online bulletin feed.
A ProductCatalog maps the business product id (the name used inside the
enterprise) to the canonical CPE that participates in CPE matching.
"""

from collections import namedtuple


class ProductCatalog(object):
    """Maps enterprise product ids to their canonical CPE strings."""

    def __init__(self):
        self._cpe_by_product = {}

    def register(self, product_id, cpe_name, display_name=None):
        self._cpe_by_product[product_id] = {
            "cpe": cpe_name,
            "display_name": display_name or product_id,
        }
        return self

    def cpe_of(self, product_id):
        entry = self._cpe_by_product.get(product_id)
        return entry["cpe"] if entry else None

    def name_of(self, product_id):
        entry = self._cpe_by_product.get(product_id)
        return entry["display_name"] if entry else product_id

    def __contains__(self, product_id):
        return product_id in self._cpe_by_product


Asset = namedtuple(
    "Asset", ["asset_id", "book_id", "business_unit", "product_id", "cpe"])


class AssetBook(object):
    """A small, named collection of assets owned by one organization."""

    def __init__(self, book_id):
        self.book_id = book_id
        self._assets = []

    def add(self, asset_id, business_unit, product_id, cpe):
        asset = Asset(
            asset_id=asset_id,
            book_id=self.book_id,
            business_unit=business_unit,
            product_id=product_id,
            cpe=cpe)
        self._assets.append(asset)
        return asset

    @property
    def assets(self):
        return tuple(self._assets)

    def __iter__(self):
        return iter(self._assets)

    def __len__(self):
        return len(self._assets)


Bulletin = namedtuple("Bulletin", ["bulletin_id", "cpe", "title"])
