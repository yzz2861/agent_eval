---
title: Object Permissions
description: How to assign object permissions.
---

# Assigning Object Permissions

Django Guardian makes assigning object permissions simple once permissions are created for models.

## Prepare permissions

Take the below example model:

``` python
class Task(models.Model):
    summary = models.CharField(max_length=32)
    content = models.TextField()
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
```

... and we want to be able to set custom permission *assign_task*.
We can let Django know about our custom permissions by adding a `permissions`
tuple to `Meta` class and our final model could look like:

``` python
class Task(models.Model):
    summary = models.CharField(max_length=32)
    content = models.TextField()
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        permissions = (
            ('assign_task', 'Assign task'),
        )
```

!!! note

    If using inheritance,
    the `Meta` class with the custom permissions
    **should** live in a abstract class.
    We recommend users to read the section "[Meta inheritance](https://docs.djangoproject.com/en/stable/topics/db/models/#meta-inheritance)"
    from the Django documentation.

After we call management commands `makemigrations` and `migrate` our
*assign_task* permission would be added to default set of permissions.

!!! note

    By default, Django adds 4 permissions for each registered model:

    -   *add_modelname*
    -   *change_modelname*
    -   *delete_modelname*
    -   *view_modelname*

    (where *modelname* is a simplified name of our model's class). See
    [https://docs.djangoproject.com/en/stable/topics/auth/default/#default-permissions](https://docs.djangoproject.com/en/stable/topics/auth/default/#default-permissions)
    for more detail.

    There is nothing new here since creation of permissions is [handled by
    django](https://docs.djangoproject.com/en/stable/topics/auth/). Now we
    can move to `assigning object permissions <assign-obj-perms>`

## Using shortcuts

We can assign permissions for any user or group and object pairs
using the convenient function: `guardian.shortcuts.assign_perm()`

### For a single object

Continuing our example we now can allow Joe user to assign some task:

``` python
>>> from django.contrib.auth.models import User
>>> boss = User.objects.create(username='Big Boss')
>>> joe = User.objects.create(username='joe')
>>> task = Task.objects.create(summary='Some job', content='', reported_by=boss)
>>> joe.has_perm('assign_task', task)
False
```

Well, not so fast Joe, let us create an object permission finally:

``` python
>>> from guardian.shortcuts import assign_perm
>>> assign_perm('assign_task', joe, task)
>>> joe.has_perm('assign_task', task)
True
```

This case doesn't really differ for group permissions assignment.
The only difference is we have to pass a `Group` instance rather than `User`.

``` python
>>> from django.contrib.auth.models import Group
>>> group = Group.objects.create(name='employees')
>>> assign_perm('change_task', group, task)
>>> joe.has_perm('change_task', task)
False
>>> # Well, joe is not yet within an *employees* group
>>> joe.groups.add(group)
>>> joe.has_perm('change_task', task)
True
```

### For multiple objects

You can assign a permission to a single user or group across many objects at
once by passing a QuerySet as the `obj` argument:

``` python
>>> tasks = Task.objects.filter(reported_by=boss)
>>> assign_perm('change_task', joe, tasks)
```

### For multiple users or groups

You can assign a permission on a single object to many users or groups at once
by passing a QuerySet as the `user_or_group` argument:

``` python
>>> users = User.objects.filter(groups__name='employees')
>>> assign_perm('change_task', users, task)
```

## Using model managers

For more direct control you can call methods on the object-permission model
manager instead of going through the shortcut. First, obtain the permission
model for your object:

``` python
>>> from guardian.utils import get_user_obj_perms_model, get_group_obj_perms_model
>>> UserObjectPermission = get_user_obj_perms_model(task)
>>> GroupObjectPermission = get_group_obj_perms_model(task)
```

### For a single object

``` python
>>> UserObjectPermission.objects.assign_perm('change_task', joe, task)
```

For a group:

``` python
>>> GroupObjectPermission.objects.assign_perm('change_task', group, task)
```

### For multiple objects

Use `bulk_assign_perm` to assign a permission to one user or group across a
QuerySet of objects:

``` python
>>> tasks = Task.objects.filter(reported_by=boss)
>>> UserObjectPermission.objects.bulk_assign_perm('change_task', joe, tasks)
```

### For multiple users or groups

Use `assign_perm_to_many` to assign a permission on one object to many users or
groups at once:

``` python
>>> users = User.objects.filter(groups__name='employees')
>>> UserObjectPermission.objects.assign_perm_to_many('change_task', users, task)
```

### Temporary grants

Object permissions accept optional `valid_from` and `valid_until` bounds. Null
bounds are permanent, so existing rows and legacy calls keep their original
meaning. The window is **left-closed, right-open**: the grant is active from
`valid_from` (inclusive) until `valid_until` (exclusive). At exactly
`valid_until` the grant is already inactive.

``` python
>>> from datetime import timedelta
>>> from django.utils import timezone
>>> now = timezone.now()
>>> assign_perm(
...     'change_task', joe, task,
...     valid_from=now,
...     valid_until=now + timedelta(days=2),
... )
```

Passing only `valid_until` creates a grant that is active immediately. Passing
only `valid_from` creates a permanent grant that activates at that instant.
Re-assigning the same user/group, permission and object with a later
`valid_until` renews the existing window; passing `None` explicitly clears a
bound and makes that side permanent.

The same window is applied by `has_perm()`/`ObjectPermissionChecker`, the
authentication backend, group inheritance, `get_objects_for_user()` and
`get_objects_for_group()`. Inactive users still never receive permissions;
superusers still receive every permission for the object.

Temporary bounds apply to object permissions only. Passing either bound with a
global permission raises `ValueError`.

Bulk assignment and removal accept the same arguments. A batch spanning
multiple content types is grouped by content type and executed in one
transaction, so a failure in any group rolls the entire batch back. Duplicate
objects/identities within a batch are de-duplicated before writing.

## Limitations

!!! warning

    **No bulk global permissions.** Passing a list or QuerySet of users/groups
    without an object is not supported. Assign global permissions one
    user/group at a time.

!!! warning

    **No dual-bulk operations.** You cannot pass lists for both
    `user_or_group` *and* `obj` at the same time. One side must be a single
    instance. Passing lists for both raises
    `guardian.exceptions.MultipleIdentityAndObjectError`.

!!! note

    **Bulk operations do not fire `post_save` signals.** Bulk assignments use
    `bulk_create()` internally, so per-object `post_save` signals are not
    sent. If you rely on signals, assign permissions individually instead.

## Assigning Permissions inside Signals

Note that the Anonymous User is created before the Permissions are
created. This may result in Django signals, e.g. `post_save` being sent
before the Permissions are created. You will need to take this into an
account when processing the signal.

``` python
@receiver(post_save, sender=User)
def user_post_save(sender, **kwargs):
    """
    Create a Profile instance for all newly created User instances. We only
    run on user creation to avoid having to check for existence on each call
    to User.save.
    """
    user, created = kwargs["instance"], kwargs["created"]
    if created and user.username != settings.ANONYMOUS_USER_NAME:
        from profiles.models import Profile
        profile = Profile.objects.create(pk=user.pk, user=user, creator=user)
        assign_perm("change_user", user, user)
        assign_perm("change_profile", user, profile)
```

The check for `user.username != settings.ANONYMOUS_USER_NAME` is
required otherwise the `assign_perm` calls will occur when the Anonymous
User is created, however before there are any permissions available.
