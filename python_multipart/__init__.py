# Copyright 2012, Andrew Dunham
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__version__ = "0.0.33"

from .exceptions import NestedMultipartError, ScopeError
from .multipart import (
    BaseParser,
    FormParser,
    MultipartParser,
    OctetStreamParser,
    QuerystringParser,
    create_form_parser,
    parse_form,
)
from .nested import (
    ApprovalPolicy,
    ApprovalScope,
    Declaration,
    NestedFormParser,
    NestedMultipartParser,
    NestedReceipt,
    NestedScope,
    PartDeclaration,
    PartPath,
    PartReceipt,
    Receipt,
    ReceiveDecision,
    ReceivePolicy,
    ReceiveReceipt,
    ReceiveScope,
    ScopeDeclaration,
    ScopeMatch,
    create_nested_form_parser,
    parse_nested_form,
    parse_nested_multipart,
)

__all__ = (
    "ApprovalPolicy",
    "ApprovalScope",
    "BaseParser",
    "Declaration",
    "FormParser",
    "MultipartParser",
    "NestedMultipartError",
    "NestedFormParser",
    "NestedMultipartParser",
    "NestedScope",
    "NestedReceipt",
    "OctetStreamParser",
    "PartDeclaration",
    "PartPath",
    "PartReceipt",
    "QuerystringParser",
    "Receipt",
    "ReceiveDecision",
    "ReceivePolicy",
    "ReceiveScope",
    "ReceiveReceipt",
    "ScopeDeclaration",
    "ScopeError",
    "ScopeMatch",
    "create_nested_form_parser",
    "create_form_parser",
    "parse_nested_form",
    "parse_nested_multipart",
    "parse_form",
)
