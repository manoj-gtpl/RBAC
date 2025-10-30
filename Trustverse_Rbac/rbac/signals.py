# ============================================================================
#  Cascading is_active Updates via Django Signals

from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Modules, Permissions, Roles, RolePermissions, UserRoles, RoleHierarchy


# ---------------- Modules → Permissions ----------------
@receiver(post_save, sender=Modules)
def cascade_module_is_active(sender, instance, **kwargs):
    """Update permissions whenever a module's active state changes"""
    with transaction.atomic():
        permissions = Permissions.objects.select_for_update().filter(module=instance)
        for perm in permissions:
            new_state = instance.is_active
            if perm.is_active != new_state:
                perm.is_active = new_state
                perm.updated_at = timezone.now()
                # Maintain deactivated_at timestamp
                perm.deactivated_at = None if new_state else timezone.now()
                perm.save(update_fields=["is_active", "updated_at", "deactivated_at"])


# ---------------- Permissions → RolePermissions ----------------
@receiver(post_save, sender=Permissions)
def cascade_permission_is_active(sender, instance, **kwargs):
    """Update role-permissions whenever a permission's active state changes"""
    with transaction.atomic():
        role_perms = RolePermissions.objects.select_for_update().filter(permission=instance)
        for rp in role_perms:
            new_state = instance.is_active and rp.role.is_active
            if rp.is_active != new_state:
                rp.is_active = new_state
                rp.updated_at = timezone.now()
                rp.save(update_fields=["is_active", "updated_at"])


# ---------------- Roles → RolePermissions, UserRoles, RoleHierarchy ----------------
@receiver(post_save, sender=Roles)
def cascade_role_is_active(sender, instance, **kwargs):
    """Update all mappings when a role's active state changes"""
    with transaction.atomic():
        # RolePermissions
        role_perms = RolePermissions.objects.select_for_update().filter(role=instance)
        for rp in role_perms:
            new_state = instance.is_active and rp.permission.is_active
            if rp.is_active != new_state:
                rp.is_active = new_state
                rp.updated_at = timezone.now()
                rp.save(update_fields=["is_active", "updated_at"])

        # UserRoles
        user_roles = UserRoles.objects.select_for_update().filter(role=instance)
        for ur in user_roles:
            new_state = instance.is_active
            if ur.is_active != new_state:
                ur.is_active = new_state
                ur.updated_at = timezone.now()
                ur.save(update_fields=["is_active", "updated_at"])

        # RoleHierarchy
        hierarchies = (RoleHierarchy.objects.select_for_update().filter(parent_role=instance) |
                       RoleHierarchy.objects.select_for_update().filter(child_role=instance))
        for rh in hierarchies:
            new_state = rh.parent_role.is_active and rh.child_role.is_active
            if rh.is_active != new_state:
                rh.is_active = new_state
                rh.updated_at = timezone.now()
                rh.save(update_fields=["is_active", "updated_at"])

# ---------------- Enforce Parent State on Child Before Save ----------------
@receiver(pre_save, sender=Permissions)
def enforce_module_state_on_permission(sender, instance, **kwargs):
    """Before saving a Permission, enforce Module's active state"""
    if instance.module and not instance.module.is_active:
        # Module inactive → force permission inactive
        instance.is_active = False
    # else → respect user-passed value (already in instance.is_active)