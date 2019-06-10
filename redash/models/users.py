# coding=utf-8
import hashlib
import itertools
import logging
import time
from functools import reduce
from operator import or_

from flask import current_app as app, url_for, request_started
from flask_login import current_user, AnonymousUserMixin, UserMixin
from passlib.apps import custom_app_context as pwd_context
from six import python_2_unicode_compatible, string_types, text_type
from sqlalchemy.exc import DBAPIError
from sqlalchemy.dialects import postgresql

from sqlalchemy_utils import EmailType
from sqlalchemy_utils.models import generic_repr

from redash import redis_connection
from redash.utils import generate_token, utcnow, dt_from_timestamp

from .base import db, Column, GFKBase
from .mixins import TimestampMixin, BelongsToOrgMixin
from .types import json_cast_property, MutableDict, MutableList

logger = logging.getLogger(__name__)


LAST_ACTIVE_KEY = 'users:last_active_at'


def sync_last_active_at():
    """
    Update User model with the active_at timestamp from Redis. We first fetch
    all the user_ids to update, and then fetch the timestamp to minimize the
    time between fetching the value and updating the DB. This is because there
    might be a more recent update we skip otherwise.
    """
    user_ids = redis_connection.hkeys(LAST_ACTIVE_KEY)
    for user_id in user_ids:
        timestamp = redis_connection.hget(LAST_ACTIVE_KEY, user_id)
        active_at = dt_from_timestamp(timestamp)
        user = User.query.filter(User.id == user_id).first()
        if user:
            user.active_at = active_at
        redis_connection.hdel(LAST_ACTIVE_KEY, user_id)
    db.session.commit()


def update_user_active_at(sender, *args, **kwargs):
    """
    Used as a Flask request_started signal callback that adds
    the current user's details to Redis
    """
    if current_user.is_authenticated and not current_user.is_api_user():
        redis_connection.hset(LAST_ACTIVE_KEY, current_user.id, int(time.time()))


def init_app(app):
    """
    A Flask extension to keep user details updates in Redis and
    sync it periodically to the database (User.details).
    """
    request_started.connect(update_user_active_at, app)


class PermissionsCheckMixin(object):
    def has_permission(self, permission):
        return self.has_permissions((permission,))

    def has_permissions(self, permissions):
        has_permissions = reduce(lambda a, b: a and b,
                                 map(lambda permission: permission in self.permissions,
                                     permissions),
                                 True)

        return has_permissions


@python_2_unicode_compatible
@generic_repr('id', 'name', 'email')
class User(TimestampMixin, db.Model, BelongsToOrgMixin, UserMixin, PermissionsCheckMixin):
    """用户帐号"""
    # id字段可以放在父类
    id = Column(db.Integer, primary_key=True)

    # 组织，组织和用户是多对一关系
    org_id = Column(db.Integer, db.ForeignKey('organizations.id'))
    org = db.relationship("Organization", backref=db.backref("users", lazy="dynamic"))

    name = Column(db.String(320))
    email = Column(EmailType)  # sqlalchemy_utils.EmailType
    _profile_image_url = Column('profile_image_url', db.String(320), nullable=True)
    password_hash = Column(db.String(128), nullable=True)
    # 用户组
    group_ids = Column('groups', MutableList.as_mutable(postgresql.ARRAY(db.Integer)), nullable=True)
    api_key = Column(db.String(40),
                     default=lambda: generate_token(40),
                     unique=True)
    # 禁用时间，如果有数据则表示禁用，为None则启用。
    disabled_at = Column(db.DateTime(True), default=None, nullable=True)
    # 详情，使用了 postgresql.JSON 类型
    details = Column(MutableDict.as_mutable(postgresql.JSON), nullable=True,
                     server_default='{}', default={})
    # 激活时间，存放在了 details 字段里
    active_at = json_cast_property(db.DateTime(True), 'details', 'active_at',
                                   default=None)
    # 是否正在邀请等待
    is_invitation_pending = json_cast_property(db.Boolean(True), 'details', 'is_invitation_pending', default=False)
    # 邮箱是否已经验证
    is_email_verified = json_cast_property(db.Boolean(True), 'details', 'is_email_verified', default=True)

    __tablename__ = 'users'
    __table_args__ = (
        # 索引又唯一的字段
        db.Index('users_org_id_email', 'org_id', 'email', unique=True),
    )

    def __str__(self):
        return u'%s (%s)' % (self.name, self.email)

    def __init__(self, *args, **kwargs):
        if kwargs.get('email') is not None:
            kwargs['email'] = kwargs['email'].lower()  # email字段全部小写
        super(User, self).__init__(*args, **kwargs)

    @property
    def is_disabled(self):
        return self.disabled_at is not None

    def disable(self):
        """禁用"""
        self.disabled_at = db.func.now()

    def enable(self):
        """使能"""
        self.disabled_at = None

    def regenerate_api_key(self):
        """重新生成APIKEY"""
        self.api_key = generate_token(40)

    def to_dict(self, with_api_key=False):
        profile_image_url = self.profile_image_url
        if self.is_disabled:
            assets = app.extensions['webpack']['assets'] or {}
            path = 'images/avatar.svg'
            profile_image_url = url_for('static', filename=assets.get(path, path))

        d = {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'profile_image_url': profile_image_url,
            'groups': self.group_ids,
            'updated_at': self.updated_at,
            'created_at': self.created_at,
            'disabled_at': self.disabled_at,
            'is_disabled': self.is_disabled,
            'active_at': self.active_at,
            'is_invitation_pending': self.is_invitation_pending,
            'is_email_verified': self.is_email_verified,
        }

        if self.password_hash is None:
            d['auth_type'] = 'external'
        else:
            d['auth_type'] = 'password'

        if with_api_key:
            d['api_key'] = self.api_key

        return d

    def is_api_user(self):
        return False

    @property
    def profile_image_url(self):
        if self._profile_image_url is not None:
            return self._profile_image_url

        email_md5 = hashlib.md5(self.email.lower()).hexdigest()
        return "https://www.gravatar.com/avatar/{}?s=40&d=identicon".format(email_md5)

    @property
    def permissions(self):
        # TODO: this should be cached.
        return list(itertools.chain(*[g.permissions for g in
                                      Group.query.filter(Group.id.in_(self.group_ids))]))

    @classmethod
    def get_by_org(cls, org):
        return cls.query.filter(cls.org == org)

    @classmethod
    def get_by_email_and_org(cls, email, org):
        return cls.get_by_org(org).filter(cls.email == email).one()

    @classmethod
    def get_by_api_key_and_org(cls, api_key, org):
        return cls.get_by_org(org).filter(cls.api_key == api_key).one()

    @classmethod
    def all(cls, org):
        """所有启用用户"""
        return cls.get_by_org(org).filter(cls.disabled_at.is_(None))

    @classmethod
    def all_disabled(cls, org):
        """所有禁用用户"""
        return cls.get_by_org(org).filter(cls.disabled_at.isnot(None))

    @classmethod
    def search(cls, base_query, term):
        """搜索用户名或邮箱
        :param base_query:
        :param term: str, 搜索关键词

        这里可以考虑使用 Flask-Whooshee 实现
        """
        term = u'%{}%'.format(term)
        search_filter = or_(cls.name.ilike(term), cls.email.like(term))

        return base_query.filter(search_filter)

    @classmethod
    def pending(cls, base_query, pending):
        """是否正在邀请中

        :param base_query:
        :param pending:
        """
        if pending:
            return base_query.filter(cls.is_invitation_pending.is_(True))
        else:
            return base_query.filter(cls.is_invitation_pending.isnot(True))  # check for both `false`/`null`

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter(cls.email == email)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """验证密码"""
        return self.password_hash and pwd_context.verify(password, self.password_hash)

    def update_group_assignments(self, group_names):
        groups = Group.find_by_name(self.org, group_names)
        groups.append(self.org.default_group)
        self.group_ids = [g.id for g in groups]
        db.session.add(self)
        db.session.commit()

    def has_access(self, obj, access_type):
        """是否允许访问
        :param obj: ORM模型对象
        :param access_type: str
        """
        return AccessPermission.exists(obj, access_type, grantee=self)

    def get_id(self):
        identity = hashlib.md5(
            "{},{}".format(self.email, self.password_hash)
        ).hexdigest()
        return u"{0}-{1}".format(self.id, identity)


@python_2_unicode_compatible
@generic_repr('id', 'name', 'type', 'org_id')
class Group(db.Model, BelongsToOrgMixin):
    """用户组

    这里是使用了用户组替代了角色？
    """

    # 默认权限
    # 我个人更喜欢使用 oauth scope 的 str:str 格式
    DEFAULT_PERMISSIONS = ['create_dashboard', 'create_query', 'edit_dashboard', 'edit_query',
                           'view_query', 'view_source', 'execute_query', 'list_users', 'schedule_query',
                           'list_dashboards', 'list_alerts', 'list_data_sources']

    BUILTIN_GROUP = 'builtin'  # 内建
    REGULAR_GROUP = 'regular'  # 正式

    id = Column(db.Integer, primary_key=True)
    # 数据源组
    data_sources = db.relationship("DataSourceGroup", back_populates="group",
                                   cascade="all")
    # 所属组织，组织与用户组是多对一关系
    org_id = Column(db.Integer, db.ForeignKey('organizations.id'))
    org = db.relationship("Organization", back_populates="groups")

    # 用户组类型
    type = Column(db.String(255), default=REGULAR_GROUP)
    # 用户组名称
    name = Column(db.String(100))
    # 该用户组的权限，没有使用多对多表，而是使用了数组
    permissions = Column(postgresql.ARRAY(db.String(255)),
                         default=DEFAULT_PERMISSIONS)
    # 创建时间
    created_at = Column(db.DateTime(True), default=db.func.now())

    __tablename__ = 'groups'

    def __str__(self):
        return text_type(self.id)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'permissions': self.permissions,
            'type': self.type,
            'created_at': self.created_at
        }

    @classmethod
    def all(cls, org):
        return cls.query.filter(cls.org == org)  # 组织过滤

    @classmethod
    def members(cls, group_id):
        return User.query.filter(User.group_ids.any(group_id))

    @classmethod
    def find_by_name(cls, org, group_names):
        result = cls.query.filter(cls.org == org, cls.name.in_(group_names))
        return list(result)


@generic_repr('id', 'object_type', 'object_id', 'access_type', 'grantor_id', 'grantee_id')
class AccessPermission(GFKBase, db.Model):
    """授予权限"""
    id = Column(db.Integer, primary_key=True)
    # 'object' defined in GFKBase
    access_type = Column(db.String(255))
    # 授予者
    grantor_id = Column(db.Integer, db.ForeignKey("users.id"))
    grantor = db.relationship(User, backref='grantor', foreign_keys=[grantor_id])
    # 被授予者
    grantee_id = Column(db.Integer, db.ForeignKey("users.id"))
    grantee = db.relationship(User, backref='grantee', foreign_keys=[grantee_id])

    __tablename__ = 'access_permissions'

    @classmethod
    def grant(cls, obj, access_type, grantee, grantor):
        """授予权限
        :param obj：ORM模型对象
        :param access_type:
        :param grantee: 被授予者
        :param grantor: 授予者
        """
        grant = cls.query.filter(cls.object_type == obj.__tablename__,
                                 cls.object_id == obj.id,
                                 cls.access_type == access_type,
                                 cls.grantee == grantee,
                                 cls.grantor == grantor).one_or_none()

        if not grant:
            grant = cls(object_type=obj.__tablename__,
                        object_id=obj.id,
                        access_type=access_type,
                        grantee=grantee,
                        grantor=grantor)
            db.session.add(grant)

        return grant

    @classmethod
    def revoke(cls, obj, grantee, access_type=None):
        """撤销
        :param obj:
        :param grantee: 被授予者
        :param access_type:
        """
        permissions = cls._query(obj, access_type, grantee)
        return permissions.delete()

    @classmethod
    def find(cls, obj, access_type=None, grantee=None, grantor=None):
        return cls._query(obj, access_type, grantee, grantor)

    @classmethod
    def exists(cls, obj, access_type, grantee):
        return cls.find(obj, access_type, grantee).count() > 0

    @classmethod
    def _query(cls, obj, access_type=None, grantee=None, grantor=None):
        """私有方法
        :param access_type:
        :param grantee: 被授予者
        :param grantor: 授予者
        """
        q = cls.query.filter(cls.object_id == obj.id,
                             cls.object_type == obj.__tablename__)

        if access_type:
            q = q.filter(AccessPermission.access_type == access_type)

        if grantee:
            q = q.filter(AccessPermission.grantee == grantee)

        if grantor:
            q = q.filter(AccessPermission.grantor == grantor)

        return q

    def to_dict(self):
        d = {
            'id': self.id,
            'object_id': self.object_id,
            'object_type': self.object_type,
            'access_type': self.access_type,
            'grantor': self.grantor_id,
            'grantee': self.grantee_id
        }
        return d


class AnonymousUser(AnonymousUserMixin, PermissionsCheckMixin):
    @property
    def permissions(self):
        return []

    def is_api_user(self):
        return False


class ApiUser(UserMixin, PermissionsCheckMixin):
    def __init__(self, api_key, org, groups, name=None):
        self.object = None
        if isinstance(api_key, string_types):
            self.id = api_key
            self.name = name
        else:
            self.id = api_key.api_key
            self.name = "ApiKey: {}".format(api_key.id)
            self.object = api_key.object
        self.group_ids = groups
        self.org = org

    def __repr__(self):
        return u"<{}>".format(self.name)

    def is_api_user(self):
        return True

    @property
    def org_id(self):
        if not self.org:
            return None
        return self.org.id

    @property
    def permissions(self):
        return ['view_query']

    def has_access(self, obj, access_type):
        return False
