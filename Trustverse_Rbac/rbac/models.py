import uuid
from django.db import models
from django.utils import timezone 
from django.db.models import Max

# 🔑 Utility function for custom ID generation
def generate_custom_id(model_cls, table_code):
    """
    Example: MOD250904001
    Format: <PREFIX><YYMMDD><SEQ>
    """
    date_part = timezone.now().strftime("%y%m%d")  # YYMMDD (e.g. 250904 for 2025-09-04)
    today_prefix = f"{table_code}{date_part}"

    # Find last sequence for this prefix
    last_id = model_cls.objects.filter(**{f"{model_cls._meta.pk.name}__startswith": today_prefix}).aggregate(
        Max(model_cls._meta.pk.name)
    )[f"{model_cls._meta.pk.name}__max"]

    if last_id:
        seq = int(last_id[-3:]) + 1
    else:
        seq = 1

    return f"{today_prefix}{seq:03d}"


# ===============================
#         MODELS
# ===============================
# 
"""Note: For case insensitive unique constraint we have created a custom collation in the DB by running the below command
    CREATE COLLATION case_insensitive (
        provider = icu,
        locale = 'und-u-ks-level2',
        deterministic = false
        ); 
    Then we have applied this collation to the required fields in the models below.
"""

# ------------ Modules -----------------
class Modules(models.Model):
    module_id = models.CharField(primary_key=True, max_length=20, editable=False)
    name = models.TextField(unique=True, db_collation="case_insensitive")
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.BigIntegerField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.BigIntegerField(blank=True, null=True)
    deactivated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "modules"
        indexes = [
            models.Index(fields=["name"], name="idx_module_name"),
        ]

    def save(self, *args, **kwargs):
        if not self.module_id:
            self.module_id = generate_custom_id(Modules, "MOD")
        # Handle deactivated_at timestamp
        if self.is_active:
            self.deactivated_at = None
        else:
            # Only set if not already set
            if not self.deactivated_at:
                self.deactivated_at = timezone.now()
        super().save(*args, **kwargs)


# ------------ Permissions -----------------
class Permissions(models.Model):
    permission_id = models.CharField(primary_key=True, max_length=20, editable=False)
    module = models.ForeignKey(Modules, on_delete=models.CASCADE, db_column="module_id")
    action = models.TextField(null=False, db_collation="case_insensitive")
    scope_hint = models.CharField(max_length=20, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.BigIntegerField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.BigIntegerField(blank=True, null=True)
    deactivated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "permissions"
        constraints = [
            models.UniqueConstraint(fields=["module", "action"], name="unique_module_action")
        ]
        indexes = [
            models.Index(fields=["module", "action"], name="idx_module_action"),
        ]

    def save(self, *args, **kwargs):
        if not self.permission_id:
            self.permission_id = generate_custom_id(Permissions, "PER")
        # Handle deactivated_at timestamp
        if self.is_active:
            self.deactivated_at = None
        else:
            # Only set if not already set
            if not self.deactivated_at:
                self.deactivated_at = timezone.now()
        super().save(*args, **kwargs)


# ------------ Roles -----------------
class Roles(models.Model):
    role_id = models.CharField(primary_key=True, max_length=20, editable=False)
    name = models.TextField(unique=True, db_collation="case_insensitive")
    description = models.TextField(blank=True, null=True)
    is_system = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.BigIntegerField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.BigIntegerField(blank=True, null=True)
    deactivated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "roles"
        indexes = [
            models.Index(fields=["name"], name="idx_role_name"),
        ]

    def save(self, *args, **kwargs):
        if not self.role_id:
            self.role_id = generate_custom_id(Roles, "ROL")
        # Handle deactivated_at timestamp
        if self.is_active:
            self.deactivated_at = None
        else:
            # Only set if not already set
            if not self.deactivated_at:
                self.deactivated_at = timezone.now()
        super().save(*args, **kwargs)


# ------------ RolePermissions -----------------
class RolePermissions(models.Model):
    role_permission_id = models.CharField(primary_key=True, max_length=20, editable=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, db_column="role_id")
    permission = models.ForeignKey(Permissions, on_delete=models.CASCADE, db_column="permission_id")
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField()  # physical column
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.BigIntegerField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "role_permissions"
        constraints = [
            models.UniqueConstraint(fields=["role", "permission"], name="unique_role_permission")
        ]
        indexes = [
            models.Index(fields=["role", "permission"], name="idx_role_permission"),
        ]

    def save(self, *args, **kwargs):
        if not self.role_permission_id:
            self.role_permission_id = generate_custom_id(RolePermissions, "RP")
        super().save(*args, **kwargs)


# ------------ UserRoles -----------------
# class UserRoles(models.Model):
#     user_role_id = models.CharField(primary_key=True, max_length=20, editable=False)
#     user_id = models.BigIntegerField()
#     role = models.ForeignKey(Roles, on_delete=models.CASCADE, db_column="role_id")
#     is_delegated = models.BooleanField(default=False)
#     valid_from = models.DateTimeField()
#     valid_to = models.DateTimeField(blank=True, null=True)
#     is_active = models.BooleanField()  # physical column
#     created_at = models.DateTimeField(auto_now_add=True)
#     created_by = models.BigIntegerField(blank=True, null=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     updated_by = models.BigIntegerField(blank=True, null=True)

#     class Meta:
#         managed = True
#         db_table = "user_roles"
#         constraints = [
#             models.UniqueConstraint(fields=["user_id", "role"], name="unique_user_role")
#         ]
#         indexes = [
#             models.Index(fields=["user_id", "role"], name="idx_user_role"),
#         ]

#     def save(self, *args, **kwargs):
#         if not self.user_role_id:
#             self.user_role_id = generate_custom_id(UserRoles, "UR")
#         super().save(*args, **kwargs)

class UserRoles(models.Model):
    user_role_id = models.CharField(primary_key=True, max_length=20, editable=False)
    
    # 🔁 Change user_id → CharField to accept TRV-style alphanumeric IDs
    user_id = models.CharField(max_length=50)  
    
    # 🔗 Keep role as FK to Roles
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, db_column="role_id")
    
    # ⚙️ New optional field for organization_id (since your payload includes it)
    organization_id = models.CharField(max_length=50, blank=True, null=True)
    
    is_delegated = models.BooleanField(default=False)
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, blank=True, null=True)  # <-- string-based
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        managed = True
        db_table = "user_roles"
        constraints = [
            models.UniqueConstraint(fields=["user_id", "role"], name="unique_user_role")
        ]
        indexes = [
            models.Index(fields=["user_id", "role"], name="idx_user_role"),
        ]

    def save(self, *args, **kwargs):
        if not self.user_role_id:
            self.user_role_id = generate_custom_id(UserRoles, "UR")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user_id} → {self.role.role_name}"



# ------------ RoleHierarchy -----------------
class RoleHierarchy(models.Model):
    role_hierarchy_id = models.CharField(primary_key=True, max_length=20, editable=False)
    parent_role = models.ForeignKey(
        Roles, on_delete=models.CASCADE, related_name="parent_roles", db_column="parent_role_id"
    )
    child_role = models.ForeignKey(
        Roles, on_delete=models.CASCADE, related_name="child_roles", db_column="child_role_id"
    )
    is_active = models.BooleanField()  # physical column
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.BigIntegerField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "role_hierarchy"
        constraints = [
            models.UniqueConstraint(fields=["parent_role", "child_role"], name="unique_parent_child")
        ]
        indexes = [
            models.Index(fields=["parent_role", "child_role"], name="idx_parent_child"),
        ]

    def save(self, *args, **kwargs):
        if not self.role_hierarchy_id:
            self.role_hierarchy_id = generate_custom_id(RoleHierarchy, "RH")
        super().save(*args, **kwargs)


# # ===============================
# # Kafaka Models
# # ===============================
# class OutboxEvent(models.Model):
#     EVENT_TYPES = [
#         ("MODULE_UPDATED", "Module Updated"),
#     ]

#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
#     payload = models.JSONField()
#     published = models.BooleanField(default=False)
#     created_at = models.DateTimeField(default=timezone.now)

#     class Meta:
#         db_table = "rbac_outbox_event"
#         ordering = ["created_at"]
#         verbose_name = "Outbox Event"
#         verbose_name_plural = "Outbox Events"


# class ProcessedEvent(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     processed_at = models.DateTimeField(default=timezone.now)

#     class Meta:
#         db_table = "rbac_processed_event"
#         ordering = ["processed_at"]
#         verbose_name = "Processed Event"
#         verbose_name_plural = "Processed Events"