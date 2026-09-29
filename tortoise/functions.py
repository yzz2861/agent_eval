from pypika_tortoise import SqlContext, analytics, functions

from tortoise.expressions import Aggregate, Function

##############################################################################
# Standard functions
##############################################################################


class Trim(Function):
    """
    Trims whitespace off edges of text.

    :samp:`Trim("{FIELD_NAME}")`
    """

    database_func = functions.Trim


class Length(Function):
    """
    Returns length of text/blob.

    :samp:`Length("{FIELD_NAME}")`
    """

    database_func = functions.Length


class Coalesce(Function):
    """
    Provides a default value if field is null.

    :samp:`Coalesce("{FIELD_NAME}", {DEFAULT_VALUE})`
    """

    database_func = functions.Coalesce


class Lower(Function):
    """
    Converts text to lower case.

    :samp:`Lower("{FIELD_NAME}")`
    """

    database_func = functions.Lower


class Upper(Function):
    """
    Converts text to upper case.

    :samp:`Upper("{FIELD_NAME}")`
    """

    database_func = functions.Upper


class _Concat(functions.Concat):
    @staticmethod
    def get_arg_sql(arg, ctx: SqlContext):
        sql = arg.get_sql(ctx.copy(with_alias=False)) if hasattr(arg, "get_sql") else str(arg)
        # explicitly convert to text for postgres to avoid errors like
        # "could not determine data type of parameter $1"
        if ctx.dialect.value == "postgresql":
            return f"{sql}::text"
        return sql


class Concat(Function):
    """
    Concate field or constant text.
    Be care, DB like sqlite3 has no support for `CONCAT`.

     :samp:`Concat("{FIELD_NAME}", {ANOTHER_FIELD_NAMES or CONSTANT_TEXT}, *args)`
    """

    database_func = _Concat


##############################################################################
# Aggregate functions
##############################################################################


class Count(Aggregate):
    """
    Counts the no of entries for that column.

    :samp:`Count("{FIELD_NAME}")`
    """

    database_func = functions.Count


class Sum(Aggregate):
    """
    Adds up all the values for that column.

    :samp:`Sum("{FIELD_NAME}")`
    """

    database_func = functions.Sum
    populate_field_object = True


class Max(Aggregate):
    """
    Returns largest value in the column.

    :samp:`Max("{FIELD_NAME}")`
    """

    database_func = functions.Max
    populate_field_object = True


class Min(Aggregate):
    """
    Returns smallest value in the column.

    :samp:`Min("{FIELD_NAME}")`
    """

    database_func = functions.Min
    populate_field_object = True


class Avg(Aggregate):
    """
    Returns average (mean) of all values in the column.

    :samp:`Avg("{FIELD_NAME}")`
    """

    database_func = functions.Avg
    populate_field_object = True


##############################################################################
# Window functions
##############################################################################


class RowNumber(Function):
    """
    Returns the number of the current row within its window partition, counting from 1.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(RowNumber(), partition_by="{FIELD_NAME}", order_by="{FIELD_NAME}")`
    """

    database_func = analytics.RowNumber

    def __init__(self) -> None:
        super().__init__(None)


class Rank(Function):
    """
    Returns the rank of the current row, with gaps.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.
    """

    database_func = analytics.Rank

    def __init__(self) -> None:
        super().__init__(None)


class DenseRank(Function):
    """
    Returns the rank of the current row, without gaps.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.
    """

    database_func = analytics.DenseRank

    def __init__(self) -> None:
        super().__init__(None)


class NTile(Function):
    """
    Distributes the rows of the partition into the given number of buckets.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(NTile({BUCKETS}), order_by="{FIELD_NAME}")`
    """

    database_func = analytics.NTile


class Lag(Function):
    """
    Returns the value of the field evaluated at the row that is ``offset`` rows
    before the current row within the partition (default 1).

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(Lag("{FIELD_NAME}"), order_by="{FIELD_NAME}")`
    """

    database_func = analytics.Lag


class Lead(Function):
    """
    Returns the value of the field evaluated at the row that is ``offset`` rows
    after the current row within the partition (default 1).

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(Lead("{FIELD_NAME}"), order_by="{FIELD_NAME}")`
    """

    database_func = analytics.Lead


class FirstValue(Function):
    """
    Returns the value of the field evaluated at the first row of the window frame.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(FirstValue("{FIELD_NAME}"), order_by="{FIELD_NAME}")`
    """

    database_func = analytics.FirstValue


class LastValue(Function):
    """
    Returns the value of the field evaluated at the last row of the window frame.

    Must be used inside a :class:`Window <tortoise.expressions.Window>` expression.

    :samp:`Window(LastValue("{FIELD_NAME}"), order_by="{FIELD_NAME}")`
    """

    database_func = analytics.LastValue
