# coding=utf-8
"""
主要的类::

    :class:Organization

"""
from six import python_2_unicode_compatible
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy_utils.models import generic_repr

from redash.settings.organization import settings as org_settings

from .base import db, Column
from .mixins import TimestampMixin
from .types import MutableDict, PseudoJSON
from .users import User, Group


@python_2_unicode_compatible
@generic_repr('id', 'name', 'slug')
class Organization(TimestampMixin, db.Model):
    """组织"""
    SETTING_GOOGLE_APPS_DOMAINS = 'google_apps_domains'
    SETTING_IS_PUBLIC = "is_public"

    id = Column(db.Integer, primary_key=True)
    name = Column(db.String(255))
    slug = Column(db.String(255), unique=True)
    settings = Column(MutableDict.as_mutable(PseudoJSON))
    # 用户组
    groups = db.relationship("Group", lazy="dynamic")
    # 事件
    events = db.relationship("Event", lazy="dynamic", order_by="desc(Event.created_at)",)

    __tablename__ = 'organizations'

    def __str__(self):
        return u'%s (%s)' % (self.name, self.id)

    @classmethod
    def get_by_slug(cls, slug):
        return cls.query.filter(cls.slug == slug).first()

    @property
    def default_group(self):
        """默认组"""
        return self.groups.filter(Group.name == 'default', Group.type == Group.BUILTIN_GROUP).first()

    @property
    def google_apps_domains(self):
        return self.settings.get(self.SETTING_GOOGLE_APPS_DOMAINS, [])

    @property
    def is_public(self):
        return self.settings.get(self.SETTING_IS_PUBLIC, False)

    @property
    def is_disabled(self):
        return self.settings.get('is_disabled', False)

    def disable(self):
        self.settings['is_disabled'] = True

    def enable(self):
        self.settings['is_disabled'] = False

    def set_setting(self, key, value):
        if key not in org_settings:
            raise KeyError(key)

        self.settings.setdefault('settings', {})
        self.settings['settings'][key] = value
        flag_modified(self, 'settings')

    def get_setting(self, key, raise_on_missing=True):
        if key in self.settings.get('settings', {}):
            return self.settings['settings'][key]

        if key in org_settings:
            return org_settings[key]

        if raise_on_missing:
            raise KeyError(key)

        return None

    @property
    def admin_group(self):
        """管理员组"""
        return self.groups.filter(Group.name == 'admin', Group.type == Group.BUILTIN_GROUP).first()

    def has_user(self, email):
        return self.users.filter(User.email == email).count() == 1
