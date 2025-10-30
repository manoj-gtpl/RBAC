from rest_framework import serializers
from .models import (
    Modules, Permissions, RoleHierarchy, RolePermissions, Roles, UserRoles
)



# ---------- BASE SERIALIZER (Reusable for all) ----------
class BaseIsActiveSerializer(serializers.ModelSerializer):
    """Ensures is_active is optional and derived if not provided."""

    class Meta:
        abstract = True
        extra_kwargs = {
            "is_active": {"required": False}
        }

    def set_is_active(self, validated_data, instance=None):
        """Hook for child serializers to override how is_active is derived."""
        return validated_data.get("is_active", getattr(instance, "is_active", True))

    def create(self, validated_data):
        validated_data["is_active"] = self.set_is_active(validated_data)
        return super().create(validated_data)




# ---------- PERMISSIONS SERIALIZER ----------
class ModulesSerializer4permissions(serializers.ModelSerializer):
    class Meta:
        model = Modules
        fields = "__all__"
class PermissionsSerializer(BaseIsActiveSerializer):
    module = ModulesSerializer4permissions(read_only=True)  # Nested for GET
    module_id = serializers.PrimaryKeyRelatedField(
        source="module",
        queryset=Modules.objects.all(),
        write_only=True
    )

    class Meta(BaseIsActiveSerializer.Meta):
        model = Permissions
        fields = "__all__"

    def set_is_active(self, validated_data, instance=None):
        # Resolve module object
        module = validated_data.get("module")
        if module and not isinstance(module, Modules):
            module = Modules.objects.filter(pk=module).first()
        elif instance:
            module = getattr(instance, "module", None)

        # If module is missing → always False
        if not module:
            return False

        # If module is inactive → always False (ignore user input)
        if not module.is_active:
            return False

        # If module is active:
        if "is_active" in validated_data:
            return validated_data["is_active"]  # respect user input
        return True  # default to True if not provided

    def validate(self, data):
        module = data.get("module")
        action = data.get("action")

        if Permissions.objects.filter(module=module, action__iexact=action).exists():
            raise serializers.ValidationError(
                {"action": f"Permission action '{action}' already exists for this module."}
            )
        return data

# ---------- MODULES SERIALIZER ----------
class ModulesSerializer(serializers.ModelSerializer):
    # Nested permissions (read-only)
    permissions = serializers.SerializerMethodField()  # compute via method

    class Meta:
        model = Modules
        fields = [
            "module_id", "name", "description", "is_active",
            "created_by", "created_at", "updated_at", "updated_by",
            "permissions"
        ]

    def get_permissions(self, obj):
        # Fetch related permissions without going back to module to avoid recursion
        perms = obj.permissions_set.all()  # assuming default related_name
        return PermissionsSerializer(perms, many=True, context=self.context).data

    def validate_name(self, value):
        if Modules.objects.filter(name__iexact=value).exists():
            raise serializers.ValidationError("Module already exists.")
        return value
    
# ---------- ROLES SERIALIZER ----------
class RolePermissionsSerializer4Role(serializers.ModelSerializer):
    permission = PermissionsSerializer(read_only=True)
    class Meta:
        model = RolePermissions
        fields = "__all__"

class RolesSerializer(serializers.ModelSerializer):
    role_permissions = RolePermissionsSerializer4Role(
        source="rolepermissions_set", many=True, read_only=True
    )
    class Meta:
        model = Roles
        fields = ["role_id", "name", "description","is_system", "is_active", "created_by", "created_at", "updated_at", "updated_by", "role_permissions"]

    def validate_name(self, value):
        if Roles.objects.filter(name__iexact=value).exists():
            raise serializers.ValidationError("Role already exists.")
        return value

# ---------- ROLE-PERMISSIONS SERIALIZER ----------
class RolePermissionsSerializer(BaseIsActiveSerializer):
    role = RolesSerializer(read_only=True)
    permission = PermissionsSerializer(read_only=True)

    role_id = serializers.CharField(write_only=True, required=True)
    permission_id = serializers.CharField(write_only=True, required=True)

    class Meta(BaseIsActiveSerializer.Meta):
        model = RolePermissions
        fields = "__all__"
        read_only_fields = ["role_permission_id", "created_at", "updated_at"]

    def set_is_active(self, validated_data, instance=None):
        # --- Resolve Role ---
        role = validated_data.get("role") or validated_data.get("role_id")
        if isinstance(role, str):
            role = Roles.objects.filter(pk=role).first()
        elif instance:
            role = getattr(instance, "role", None)

        # --- Resolve Permission ---
        permission = validated_data.get("permission") or validated_data.get("permission_id")
        if isinstance(permission, str):
            permission = Permissions.objects.filter(pk=permission).first()
        elif instance:
            permission = getattr(instance, "permission", None)

        # If either is missing → inactive
        if not role or not permission:
            return False

        # If role or permission inactive → always False
        if not (role.is_active and permission.is_active):
            return False

        # If both active → respect user input if provided, else default True
        if "is_active" in validated_data:
            return validated_data["is_active"]
        return True



# # ---------- USER-ROLES SERIALIZER ----------
# class UserRolesSerializer(BaseIsActiveSerializer):
#     role = RolesSerializer(read_only=True)  # Nested for GET
#     role_id = serializers.CharField(write_only=True, required=True)  # Accept role_id for POST/PUT
#     class Meta(BaseIsActiveSerializer.Meta):
#         model = UserRoles
#         fields = "__all__"

#     def set_is_active(self, validated_data, instance=None):
#         if "is_active" in validated_data:
#             return validated_data["is_active"]

#         role = validated_data.get("role")
#         if role and not isinstance(role, Roles):
#             role = Roles.objects.filter(pk=role).first()
#         elif instance:
#             role = getattr(instance, "role", None)

#         return role.is_active if role else False

class UserRolesSerializer(serializers.ModelSerializer):
    role = RolesSerializer(read_only=True)  # Nested role info (for GET)
    role_id = serializers.CharField(write_only=True, required=True)  # for POST
    
    class Meta:
        model = UserRoles
        fields = "__all__"
    
    def create(self, validated_data):
        # Extract role_id and replace with actual Role object
        role_id = validated_data.pop("role_id", None)
        if role_id:
            role = Roles.objects.filter(role_id=role_id).first()
            validated_data["role"] = role
        return super().create(validated_data)

# ---------- ROLE-HIERARCHY SERIALIZER ----------
class RoleHierarchySerializer(BaseIsActiveSerializer):
    parent_role = RolesSerializer(read_only=True)
    child_role = RolesSerializer(read_only=True)

    parent_role_id = serializers.CharField(write_only=True, required=True)
    child_role_id = serializers.CharField(write_only=True, required=True)
    class Meta(BaseIsActiveSerializer.Meta):
        model = RoleHierarchy
        fields = "__all__"

    def set_is_active(self, validated_data, instance=None):
        if "is_active" in validated_data:
            return validated_data["is_active"]

        parent_role = validated_data.get("parent_role")
        child_role = validated_data.get("child_role")

        if parent_role and not isinstance(parent_role, Roles):
            parent_role = Roles.objects.filter(pk=parent_role).first()
        elif instance:
            parent_role = getattr(instance, "parent_role", None)

        if child_role and not isinstance(child_role, Roles):
            child_role = Roles.objects.filter(pk=child_role).first()
        elif instance:
            child_role = getattr(instance, "child_role", None)

        return (parent_role.is_active if parent_role else False) and \
               (child_role.is_active if child_role else False)

# ---------- (OPTIONAL) SOD FORBIDDEN PAIRS ----------
# class SodForbiddenPairsSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = SodForbiddenPairs
#         fields = '__all__'  # Include all fields if enabled


# # ---------- (OPTIONAL) SOD POLICIES ----------
# class SodPoliciesSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = SodPolicies
#         fields = '__all__'  # Include all fields if enabled
