import json
import unittest

from peewee import SqliteDatabase
from peewee import ForeignKeyField
from peewee import IntegerField
from peewee import Case
from peewee import Model
from peewee import Select
from peewee import SQL
from peewee import Table
from peewee import TextField
from peewee import Value
from peewee import fn
from playhouse.query_description import FORMAT
from playhouse.query_description import InvalidQueryDescriptionError
from playhouse.query_description import QueryDescriptionError
from playhouse.query_description import QueryRegistry
from playhouse.query_description import UnsupportedNodeError
from playhouse.query_description import dumps_query
from playhouse.query_description import loads_query


database = SqliteDatabase(':memory:')


class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    name = TextField()
    score = IntegerField()


class Category(BaseModel):
    name = TextField(unique=True)
    parent = ForeignKeyField('self', null=True, backref='children')


class Tweet(BaseModel):
    user = ForeignKeyField(User)
    body = TextField()


registry = QueryRegistry()
registry.register_model(User, 'app.User')
registry.register_model(Tweet, 'app.Tweet')
registry.register_model(Category, 'app.Category')


class QueryDescriptionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.bind([User, Tweet, Category])
        database.connect()
        database.create_tables([User, Tweet, Category])

    @classmethod
    def tearDownClass(cls):
        database.drop_tables([User, Tweet, Category])
        database.close()

    def setUp(self):
        Tweet.delete().execute()
        User.delete().execute()
        Category.delete().execute()

    def assertQueryRoundTrip(self, query):
        description = dumps_query(query, registry)
        encoded = json.dumps(description, allow_nan=False)
        restored = loads_query(json.loads(encoded), registry)
        self.assertEqual(query.sql(), restored.sql())
        return description, restored

    def test_select_conditions_ordering_functions(self):
        huey = User.create(name='huey', score=10)
        User.create(name='mickey', score=20)
        Tweet.create(user=huey, body='Hello')

        query = (
            User
            .select(User, fn.LOWER(User.name).alias('lower_name'))
            .where((User.score >= 5) &
                   (User.name << ['huey', 'mickey']))
            .order_by(User.score.desc(nulls='last'), User.id)
            .limit(10)
            .offset(1))

        description, restored = self.assertQueryRoundTrip(query)
        self.assertEqual(description['format'], FORMAT)
        self.assertEqual(description['version'], 1)
        self.assertEqual([u.id for u in restored], [huey.id])

    def test_aggregate_filter_distinct_grouping(self):
        huey = User.create(name='huey', score=10)
        User.create(name='mickey', score=20)
        Tweet.create(user=huey, body='first')
        Tweet.create(user=huey, body='second')

        query = (
            User
            .select(User.id, fn.COUNT(Tweet.id.distinct()).alias('ct'))
            .join(Tweet, on=(Tweet.user == User.id))
            .group_by(User.id)
            .having(fn.COUNT(Tweet.id.distinct()) > 0)
            .order_by(User.id))
        description, restored = self.assertQueryRoundTrip(query)
        self.assertEqual(list(restored.tuples()), [(huey.id, 2)])

    def test_registered_custom_function(self):
        registry.register_function('APP_LEX', 'lex')
        User.create(name='Huey', score=1)

        query = User.select(fn.lex(User.name).alias('lex_name')).tuples()
        database.register_function(str.lower, 'lex', 1, deterministic=True)
        _, restored = self.assertQueryRoundTrip(query)
        self.assertEqual(list(restored), [('huey',)])

    def test_join_model_graph_and_explicit_alias(self):
        huey = User.create(name='huey', score=10)
        mickey = User.create(name='mickey', score=20)
        first = Tweet.create(user=huey, body='first')
        Tweet.create(user=mickey, body='second')

        author = User.alias('author')
        query = (
            Tweet
            .select(Tweet, author)
            .join(author, on=(author.id == Tweet.user))
            .where(author.name == 'huey')
            .order_by(Tweet.id))

        _, restored = self.assertQueryRoundTrip(query)
        tweets = list(restored)
        self.assertEqual([tweet.id for tweet in tweets], [first.id])
        self.assertEqual(tweets[0].user.id, huey.id)
        self.assertEqual(tweets[0].user.name, 'huey')

    def test_shared_correlated_subquery(self):
        huey = User.create(name='huey', score=10)
        User.create(name='mickey', score=20)
        tweet = Tweet.create(user=huey, body='Hello')

        subquery = (
            User
            .select(fn.COUNT(User.id))
            .where(User.id == Tweet.user_id))
        query = (
            Tweet
            .select(Tweet.body, subquery.alias('tweet_count'))
            .where(fn.EXISTS(User.select(User.id).where(
                User.id == Tweet.user_id)))
            .order_by(Tweet.id))

        description, restored = self.assertQueryRoundTrip(query)
        self.assertEqual(list(restored.tuples()), [(tweet.body, 1)])
        select_ids = [node_id for node_id, node in description['nodes'].items()
                      if node['type'] == 'model_select']
        self.assertEqual(len(select_ids), 3)

    def test_recursive_cte(self):
        root = Category.create(name='root')
        child = Category.create(name='child', parent=root)
        grandchild = Category.create(name='grandchild', parent=child)

        base = (
            Category
            .select(Category.id, Category.name, Category.parent)
            .where(Category.name == 'root')
            .cte('tree', recursive=True, columns=('id', 'name', 'parent_id')))
        recursive_alias = Category.alias('c')
        recursive_term = (
            recursive_alias
            .select(recursive_alias.id, recursive_alias.name,
                    recursive_alias.parent)
            .join(base, on=(recursive_alias.parent == base.c.id)))
        cte = base.union_all(recursive_term)
        query = (
            cte
            .select_from(cte.c.name)
            .order_by(cte.c.name.desc()))

        _, restored = self.assertQueryRoundTrip(query)
        self.assertEqual([row[0] for row in restored.tuples()],
                         ['root', 'grandchild', 'child'])

    def test_table_star_case_cast_and_union(self):
        event = Table('event', ('id', 'kind', 'score'))
        registry.register_table(event, 'app.event')
        score_case = Case(None, ((event.score > 10, 'high'),), 'low')
        lhs = event.select(event.id, score_case.alias('bucket'))
        rhs = event.select(event.id, Value('other').cast('TEXT'))
        query = (lhs | rhs).order_by(event.id)
        self.assertQueryRoundTrip(query)

        star_query = event.select(event.__star__).where(event.kind == 'login')
        self.assertQueryRoundTrip(star_query)

    def test_generic_select_infers_database_from_registered_model(self):
        huey = User.create(name='huey', score=1)
        query = Select((User,), (User.id, User.name)).where(User.id == huey.id)
        _, restored = self.assertQueryRoundTrip(query)
        self.assertEqual(list(restored.tuples()), [(huey.id, 'huey')])

    def test_shared_cte_used_twice(self):
        active_users = (
            User.select(User.id, User.name)
            .where(User.score > 0)
            .cte('active_users'))
        first = active_users.select_from(active_users.c.name)
        second = active_users.select_from(active_users.c.id)
        query = first.union_all(second).with_cte(active_users)
        description, restored = self.assertQueryRoundTrip(query)
        cte_nodes = [node for node in description['nodes'].values()
                     if node['type'] == 'cte']
        self.assertEqual(len(cte_nodes), 1)

    def test_values_remain_separate_from_expressions(self):
        query = (
            User
            .select(User)
            .where((User.score + 1) > Value(5, User.score.db_value)))
        description, _ = self.assertQueryRoundTrip(query)
        for node in description['nodes'].values():
            self.assertNotIn('database', node)
        self.assertIn({'type': 'integer', 'value': 5}, description['values'])

    def test_unsupported_raw_sql_reports_path(self):
        from peewee import SQL
        query = User.select(User.id, SQL('ROW_NUMBER() OVER ()'))
        with self.assertRaises(UnsupportedNodeError) as ctx:
            dumps_query(query, registry)
        self.assertEqual(ctx.exception.path, '$.columns[1]')

    def test_unknown_function_reports_path(self):
        query = User.select(fn.EVIL(User.id))
        with self.assertRaises(QueryDescriptionError) as ctx:
            dumps_query(query, registry)
        self.assertEqual(ctx.exception.args[0], 'Function EVIL is not whitelisted.')

    def test_decode_does_not_accept_arbitrary_sql_node(self):
        description = dumps_query(User.select(User.id), registry)
        root_id = description['root']['id']
        description['nodes'][root_id]['columns'][0] = {
            'type': 'sql', 'sql': 'DELETE FROM "user"'}
        with self.assertRaises(InvalidQueryDescriptionError) as ctx:
            loads_query(description, registry)
        self.assertIn('$.nodes.' + root_id + '.columns[0]',
                      str(ctx.exception))

    def test_decode_rejects_reference_cycle(self):
        description = dumps_query(User.select(User.id), registry)
        root_id = description['root']['id']
        description['nodes'][root_id]['where'] = {'$ref': 'nodes',
                                                  'id': root_id}
        with self.assertRaises(InvalidQueryDescriptionError) as ctx:
            loads_query(description, registry)
        self.assertIn('reference cycle', str(ctx.exception))

    def test_decode_rejects_database_hint(self):
        description = dumps_query(User.select(User.id), registry)
        description['database'] = 'postgres://user:pass@host/app'
        with self.assertRaises(InvalidQueryDescriptionError):
            loads_query(description, registry)

    def test_description_contains_no_database_information(self):
        description = dumps_query(User.select(User.id), registry)
        encoded = json.dumps(description)
        self.assertNotIn(':memory:', encoded)
        self.assertNotIn('SqliteDatabase', encoded)


if __name__ == '__main__':
    unittest.main()
