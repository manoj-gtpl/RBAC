from django.core.cache import cache
from django.db import transaction
from rest_framework.response import Response
from django.db.models import Prefetch
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.utils import timezone
from rest_framework.pagination import PageNumberPagination
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import (
    Modules, Permissions, RolePermissions, Roles, RoleHierarchy,UserRoles
)
from .serializers import (
    ModulesSerializer, PermissionsSerializer,
    RolePermissionsSerializer, RolesSerializer,RolePermissionsSerializer,UserRolesSerializer,RoleHierarchySerializer
)

""""
# ==========================================
#   CACHE UTILITIES
# ==========================================

CACHE_TTL = 60 * 1  # 1 hour  (tune per project)

def _cache_key(model_name, obj_id=None):
    # Generate cache key for list or object.
    if obj_id:
        return f"rbac:{model_name}:{obj_id}"
    return f"rbac:{model_name}:list"

def get_from_cache(model_name, obj_id=None):
    return cache.get(_cache_key(model_name, obj_id))

def set_in_cache(model_name, value, obj_id=None):
    cache.set(_cache_key(model_name, obj_id), value, CACHE_TTL)

def clear_cache(model_name, obj_id=None):
    # Clear cache for one object or entire list.
    cache.delete(_cache_key(model_name, obj_id))
    if obj_id:  # also clear list cache on object change
        cache.delete(_cache_key(model_name))


# ==========================================
#   BASE CACHED VIEWSET
# ==========================================

class CachedModelViewSet(viewsets.ModelViewSet):

    # Base ViewSet with Redis caching for list & retrieve.
    # Child classes must set:
    #     - model
    #     - serializer_class

    model = None  # must be overridden

    def list(self, request, *args, **kwargs):
        model_name = self.model.__name__.lower()
        data = get_from_cache(model_name)

        if not data:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            data = serializer.data
            set_in_cache(model_name, data)

        return Response(data)   # ✅ fixed

    def retrieve(self, request, *args, **kwargs):
        model_name = self.model.__name__.lower()
        obj_id = kwargs.get("pk")
        data = get_from_cache(model_name, obj_id)

        if not data:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            data = serializer.data
            set_in_cache(model_name, data, obj_id)

        return Response(data)   # ✅ fixed

    def perform_create(self, serializer):
        instance = serializer.save()

        def _clear():
            clear_cache(self.model.__name__.lower())
        transaction.on_commit(_clear)

        return instance

    def perform_update(self, serializer):
        instance = serializer.save()

        def _clear():
            clear_cache(self.model.__name__.lower(), instance.pk)
        transaction.on_commit(_clear)

        return instance

    def perform_destroy(self, instance):
        pk = instance.pk
        instance.delete()

        def _clear():
            clear_cache(self.model.__name__.lower(), pk)
        transaction.on_commit(_clear)
"""
# ==========================================
#   RBAC VIEWSETS 
# ==========================================

class ModulesViewSet(viewsets.ModelViewSet):
    model = Modules
    queryset = Modules.objects.prefetch_related('permissions_set')
    serializer_class = ModulesSerializer
    http_method_names = ['get', 'post', 'patch']


class PermissionsViewSet(viewsets.ModelViewSet):
    model = Permissions
    queryset = Permissions.objects.all()
    serializer_class = PermissionsSerializer
    http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']

    def get_queryset(self):
        queryset = super().get_queryset()

        # ✅ Filter by module_id if query param exists
        module_id = self.request.query_params.get("module")
        if module_id:
            queryset = queryset.filter(module__module_id=module_id)

        return queryset


class RolePermissionsPagination(PageNumberPagination):
    page_size = 50  # 50 items per page
    page_size_query_param = "page_size"
    max_page_size = 100

class RolePermissionsViewSet(viewsets.ModelViewSet):
    model = RolePermissions
    queryset = RolePermissions.objects.all()
    serializer_class = RolePermissionsSerializer
    pagination_class = RolePermissionsPagination  # ✅ Add pagination here
    http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']


# class RolesViewSet(viewsets.ModelViewSet):
#     model = Roles
#     queryset = Roles.objects.all()
#     serializer_class = RolesSerializer
#     pagination_class = RolePermissionsPagination
#     http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']

    # def create(self, request, *args, **kwargs):
    #     """
    #     Create a role. If 'permissions' are provided, also create role-permissions.
    #     Payload example:
    #     {
    #         "name": "Branch Manager",
    #         "description": "Supervises branch operations",
    #         "permissions": ["PER250909029", "PER250909030"]   # optional
    #     }
    #     """
    #     role_name = request.data.get("name")
    #     role_desc = request.data.get("description")
    #     created_by = request.data.get("created_by", 101)
    #     updated_by = request.data.get("updated_by", 101)
    #     permissions_ids = request.data.get("permissions", [])

    #     if not role_name:
    #         return Response({"detail": "Role name is required."}, status=status.HTTP_400_BAD_REQUEST)

    #     try:
    #         with transaction.atomic():
    #             # 1️⃣ Create the role
    #             role = Roles.objects.create(name=role_name, description=role_desc,
    #                                         created_by=created_by, updated_by=updated_by)

    #             role_permissions_data = []

    #             # 2️⃣ Only create role-permissions if permissions are provided
    #             if permissions_ids:
    #                 for perm_id in permissions_ids:
    #                     permission = Permissions.objects.get(permission_id=perm_id)
    #                     rp = RolePermissions.objects.create(
    #                         role=role,
    #                         permission=permission,
    #                         valid_from=timezone.now(),
    #                         created_by=created_by, 
    #                         updated_by=updated_by,
    #                         is_active=True
    #                     )
    #                     role_permissions_data.append(rp)

    #             # 3️⃣ Serialize response
    #             role_data = RolesSerializer(role).data
    #             rp_data = RolePermissionsSerializer(role_permissions_data, many=True).data

    #             return Response({"role": role_data, "role_permissions": rp_data}, status=status.HTTP_201_CREATED)

    #     except Permissions.DoesNotExist:
    #         return Response({"detail": "One or more permissions not found."}, status=status.HTTP_400_BAD_REQUEST)
    #     except Exception as e:
    #         return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class RolesViewSet(viewsets.ModelViewSet):
    queryset = Roles.objects.all()
    serializer_class = RolesSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a role. If 'permissions' are provided, also create role-permissions.
        Special handling: if 'MOD251004001' is present (either directly in permissions list),
        assign ALL active permissions to the created role.
        """
        role_name = request.data.get("name")
        role_desc = request.data.get("description")
        created_by = request.data.get("created_by", 101)
        updated_by = request.data.get("updated_by", 101)
        permissions_ids = request.data.get("permissions", [])  # list of permission_ids OR ["MOD251004001"]

        if not role_name:
            return Response({"detail": "Role name is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # 1️⃣ Create the role
                role = Roles.objects.create(
                    name=role_name,
                    description=role_desc,
                    created_by=created_by,
                    updated_by=updated_by
                )

                role_permissions_data = []

                # 2️⃣ Create role-permissions if permissions are provided
                if permissions_ids:
                    # Special handling for "ALL MODULE" assignment
                    if "MOD251004001" in permissions_ids:
                        # Fetch all active permissions (excluding disabled modules)
                        all_perms = Permissions.objects.filter(
                            module__is_active=True,
                            is_active=True
                        )
                        for p in all_perms:
                            rp, created = RolePermissions.objects.get_or_create(
                                role=role,
                                permission=p,
                                defaults={
                                    "valid_from": timezone.now(),
                                    "created_by": created_by,
                                    "updated_by": updated_by,
                                    "is_active": True
                                }
                            )
                            role_permissions_data.append(rp)
                    else:
                        # Normal permission ids
                        for perm_id in permissions_ids:
                            permission = Permissions.objects.filter(permission_id=perm_id).first()
                            if not permission:
                                continue
                            rp, created = RolePermissions.objects.get_or_create(
                                role=role,
                                permission=permission,
                                defaults={
                                    "valid_from": timezone.now(),
                                    "created_by": created_by,
                                    "updated_by": updated_by,
                                    "is_active": True
                                }
                            )
                            role_permissions_data.append(rp)

                # 3️⃣ Serialize response
                role_data = RolesSerializer(role).data
                rp_data = RolePermissionsSerializer(role_permissions_data, many=True).data

                return Response(
                    {"role": role_data, "role_permissions": rp_data},
                    status=status.HTTP_201_CREATED
                )

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def list(self, request, *args, **kwargs):
        """
        Return all roles with their permissions + modules
        """
        queryset = self.get_queryset().prefetch_related(
            "rolepermissions_set__permission__module"
        )
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        """
        Return a single role with its permissions + modules
        """
        role = self.get_object()
        serializer = self.get_serializer(role)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    # def update(self, request, *args, **kwargs):
    #     """
    #     Update Role with:
    #     - name & description
    #     - remove role-permissions
    #     - update existing role-permissions (is_active)
    #     - add new role-permissions (from moduleId + permissionId objects)
    #     """
    #     instance = self.get_object()

    #     role_name = request.data.get("name", instance.name)
    #     role_desc = request.data.get("description", instance.description)
    #     updated_by = request.data.get("updated_by", 101)

    #     removed_ids = request.data.get("removedRolePermissionIds", [])
    #     new_modules = request.data.get("newModules", [])
    #     update_rps = request.data.get("updateRolePermissions", [])

    #     print("📝 Incoming payload:")
    #     print("Name:", role_name)
    #     print("Description:", role_desc)
    #     print("Removed IDs:", removed_ids)
    #     print("New Modules:", new_modules)
    #     print("Update RolePermissions:", update_rps)

    #     try:
    #         with transaction.atomic():
    #             # 1️⃣ Update role fields
    #             instance.name = role_name
    #             instance.description = role_desc
    #             instance.updated_by = updated_by
    #             instance.save()
    #             print(f"✅ Role {instance.role_id} updated with new name/description")

    #             # 2️⃣ Remove role-permissions
    #             if removed_ids:
    #                 deleted_count, _ = RolePermissions.objects.filter(
    #                     role=instance,
    #                     role_permission_id__in=removed_ids
    #                 ).delete()
    #                 print(f"🗑 Removed {deleted_count} role-permissions")

    #             # 3️⃣ Update existing role-permissions
    #             if update_rps:
    #                 updated_count = 0
    #                 for rp_obj in update_rps:
    #                     rp_id = rp_obj.get("rolePermissionId")
    #                     is_active = rp_obj.get("isActive")
    #                     if not rp_id:
    #                         print("⚠ Skipping invalid rolePermissionId:", rp_obj)
    #                         continue

    #                     rp_instance = RolePermissions.objects.filter(
    #                         role_permission_id=rp_id, role=instance
    #                     ).first()
    #                     if not rp_instance:
    #                         print(f"⚠ RolePermission {rp_id} not found for role {instance.role_id}")
    #                         continue

    #                     rp_instance.is_active = is_active
    #                     rp_instance.updated_by = updated_by
    #                     rp_instance.updated_at = timezone.now()
    #                     rp_instance.save()
    #                     updated_count += 1
    #                     print(f"🔄 Updated RolePermission {rp_id} is_active={is_active}")

    #                 print(f"✅ Updated {updated_count} existing role-permissions")

    #             # 4️⃣ Add new role-permissions
    #             created_rps = []
    #             for module_data in new_modules:
    #                 module_id = module_data.get("moduleId")
    #                 permissions_data = module_data.get("permissions", [])

    #                 for perm_obj in permissions_data:
    #                     perm_id = perm_obj.get("permissionId")
    #                     if not perm_id:
    #                         print("⚠ Skipping invalid permissionId in newModules:", perm_obj)
    #                         continue

    #                     permission = Permissions.objects.filter(permission_id=perm_id).first()
    #                     if not permission:
    #                         print(f"❌ Permission {perm_id} not found, skipping")
    #                         continue

    #                     rp = RolePermissions.objects.create(
    #                         role=instance,
    #                         permission=permission,
    #                         valid_from=timezone.now(),
    #                         created_by=instance.created_by,
    #                         updated_by=updated_by,
    #                         is_active=True,
    #                     )
    #                     created_rps.append(rp)
    #                     print(f"➕ Created new RolePermission {rp.role_permission_id}")

    #             # 5️⃣ Response
    #             role_data = RolesSerializer(instance).data
    #             rp_data = RolePermissionsSerializer(
    #                 instance.rolepermissions_set.all(), many=True
    #             ).data

    #             return Response(
    #                 {"role": role_data, "role_permissions": rp_data},
    #                 status=status.HTTP_200_OK,
    #             )

    #     except Exception as e:
    #         print("❌ Exception during role update:", str(e))
    #         return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def update(self, request, *args, **kwargs):
        """
        Update Role with:
        - name & description
        - remove role-permissions
        - update existing role-permissions (is_active)
        - add new role-permissions (from moduleId + permissionId objects)
        Special handling: if a module in newModules has moduleId == 'MOD251004001',
        assign ALL active permissions to the role.
        """
        instance = self.get_object()

        role_name = request.data.get("name", instance.name)
        role_desc = request.data.get("description", instance.description)
        updated_by = request.data.get("updated_by", 101)

        removed_ids = request.data.get("removedRolePermissionIds", [])
        new_modules = request.data.get("newModules", [])
        update_rps = request.data.get("updateRolePermissions", [])

        print("📝 Incoming payload:")
        print("Name:", role_name)
        print("Description:", role_desc)
        print("Removed IDs:", removed_ids)
        print("New Modules:", new_modules)
        print("Update RolePermissions:", update_rps)

        try:
            with transaction.atomic():
                # 1️⃣ Update role fields
                instance.name = role_name
                instance.description = role_desc
                instance.updated_by = updated_by
                instance.save()
                print(f"✅ Role {instance.role_id} updated with new name/description")

                # 2️⃣ Remove role-permissions
                if removed_ids:
                    deleted_count, _ = RolePermissions.objects.filter(
                        role=instance,
                        role_permission_id__in=removed_ids
                    ).delete()
                    print(f"🗑 Removed {deleted_count} role-permissions")

                # 3️⃣ Update existing role-permissions
                if update_rps:
                    updated_count = 0
                    for rp_obj in update_rps:
                        rp_id = rp_obj.get("rolePermissionId")
                        is_active = rp_obj.get("isActive")
                        if not rp_id:
                            print("⚠ Skipping invalid rolePermissionId:", rp_obj)
                            continue

                        rp_instance = RolePermissions.objects.filter(
                            role_permission_id=rp_id, role=instance
                        ).first()
                        if not rp_instance:
                            print(f"⚠ RolePermission {rp_id} not found for role {instance.role_id}")
                            continue

                        rp_instance.is_active = is_active
                        rp_instance.updated_by = updated_by
                        rp_instance.updated_at = timezone.now()
                        rp_instance.save()
                        updated_count += 1
                        print(f"🔄 Updated RolePermission {rp_id} is_active={is_active}")

                    print(f"✅ Updated {updated_count} existing role-permissions")

                # 4️⃣ Add new role-permissions (handle special ALL module)
                created_rps = []
                for module_data in new_modules:
                    module_id = module_data.get("moduleId")
                    permissions_data = module_data.get("permissions", [])

                    # If the special ALL module is requested
                    if module_id == "MOD251004001":
                        all_permissions = Permissions.objects.filter(module__is_active=True, is_active=True)
                        for permission in all_permissions:
                            rp, created = RolePermissions.objects.get_or_create(
                                role=instance,
                                permission=permission,
                                defaults={
                                    "valid_from": timezone.now(),
                                    "created_by": instance.created_by,
                                    "updated_by": updated_by,
                                    "is_active": True,
                                }
                            )
                            if created:
                                created_rps.append(rp)
                                print(f"➕ Assigned ALL permission {permission.permission_id} to role {instance.role_id}")
                        # skip processing permissions_data for this module_data
                        continue

                    # Normal module + permissions flow
                    for perm_obj in permissions_data:
                        perm_id = perm_obj.get("permissionId")
                        if not perm_id:
                            print("⚠ Skipping invalid permissionId in newModules:", perm_obj)
                            continue

                        permission = Permissions.objects.filter(permission_id=perm_id).first()
                        if not permission:
                            print(f"❌ Permission {perm_id} not found, skipping")
                            continue

                        rp, created = RolePermissions.objects.get_or_create(
                            role=instance,
                            permission=permission,
                            defaults={
                                "valid_from": timezone.now(),
                                "created_by": instance.created_by,
                                "updated_by": updated_by,
                                "is_active": True,
                            }
                        )
                        if created:
                            created_rps.append(rp)
                            print(f"➕ Created new RolePermission {rp.role_permission_id}")

                # 5️⃣ Response
                role_data = RolesSerializer(instance).data
                rp_data = RolePermissionsSerializer(
                    instance.rolepermissions_set.all(), many=True
                ).data

                return Response(
                    {"role": role_data, "role_permissions": rp_data},
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            print("❌ Exception during role update:", str(e))
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=["get"], url_path="search")
    def search_role(self, request):
        """
        Search for a role by 'role_id' passed as query param:
        /rbac/roles/search/?role_id=ROL251021001
        Returns role details + associated permissions + modules.
        """
        role_id = request.query_params.get("role_id")
        if not role_id:
            return Response(
                {"error": "role_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        role = Roles.objects.filter(role_id=role_id).first()
        if not role:
            return Response(
                {"error": f"Role {role_id} not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Serialize role
        role_data = RolesSerializer(role).data

        # Serialize role-permissions with module info
        rp_qs = RolePermissions.objects.filter(role=role).select_related("permission__module")
        rp_data = RolePermissionsSerializer(rp_qs, many=True).data

        return Response(
            {"role": role_data, "role_permissions": rp_data},
            status=status.HTTP_200_OK
        )
    
class UserRolesViewSet(viewsets.ModelViewSet):
    queryset = UserRoles.objects.all()
    serializer_class = UserRolesSerializer
    http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']

    def get_queryset(self):
        queryset = (
            UserRoles.objects
            .select_related("role")
            .prefetch_related(
                # Prefetch rolepermissions separately
                Prefetch(
                    "role__rolepermissions_set",
                    queryset=RolePermissions.objects
                        .select_related("permission__module")
                        .filter(is_active=True),
                    to_attr="cached_role_permissions"  # ✅ avoids hitting DB later
                )
            )
        )

        user_id = self.request.query_params.get("user_id")
        if user_id:
            queryset = queryset.filter(user_id=user_id)

        role_id = self.request.query_params.get("role_id")
        if role_id:
            queryset = queryset.filter(role_id=role_id)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        return Response(self._build_response(queryset))

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        return Response(self._build_response([instance]))

    def _build_response(self, queryset):
        """
        Build final structure in a single loop without nested serializer calls.
        """
        if not queryset:
            return {}

        user_id = queryset[0].user_id

        roles, permissions, modules = {}, {}, {}

        for ur in queryset:
            role = ur.role
            # roles[role.role_id] = {
            #     "role_id": role.role_id,
            #     "name": role.name,
            #     "is_active": role.is_active,
            # }
            roles[role.role_id] = RolesSerializer(role).data

            # ✅ Use prefetched RolePermissions
            for rp in getattr(role, "cached_role_permissions", []):
                perm = rp.permission
                module = perm.module

                permissions[perm.permission_id] = PermissionsSerializer(perm).data
                modules[module.module_id] = ModulesSerializer(module).data

                # permissions[perm.permission_id] = {
                #     "permission_id": perm.permission_id,
                #     "action": perm.action,
                #     "is_active": perm.is_active,
                #     "module_id": module.module_id,
                # }

                # modules[module.module_id] = {
                #     "module_id": module.module_id,
                #     "name": module.name,
                #     "description": module.description,
                #     "is_active": module.is_active,
                # }

        return {
            "user_id": user_id,
            "roles": list(roles.values()),
            "permissions": list(permissions.values()),
            "modules": list(modules.values()),
        }

class RoleHierarchyViewSet(viewsets.ModelViewSet):
    model = RoleHierarchy
    queryset = RoleHierarchy.objects.all()
    serializer_class = RoleHierarchySerializer
    http_method_names = ['get', 'post', 'put', 'patch', 'head', 'options']



@csrf_exempt
def get_roles(request):
    """
    Returns all roles if no 'name' query parameter is provided.
    If 'name' is provided, returns only the role_id for that role.
    """
    if request.method == "GET":
        role_name = request.GET.get("name")

        if role_name:
            # Fetch the specific role by name (case-insensitive)
            try:
                role = Roles.objects.get(name__iexact=role_name)
                return JsonResponse({
                    "role_name": role.name,
                    "role_id": role.role_id
                }, status=200)
            except Roles.DoesNotExist:
                return JsonResponse({
                    "error": f"Role with name '{role_name}' not found."
                }, status=404)
        else:
            # Fetch all roles
            roles = list(Roles.objects.filter(is_active=True).values("role_id", "name", "description"))
            return JsonResponse({
                "roles": roles
            }, status=200)
    
    return JsonResponse({"error": "Invalid request method"}, status=405)

