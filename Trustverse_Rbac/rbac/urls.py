from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ModulesViewSet, PermissionsViewSet,
    RolePermissionsViewSet, RolesViewSet,UserRolesViewSet,RoleHierarchyViewSet
)

# Initialize DRF router
router = DefaultRouter()

# Register all API endpoints
router.register(r'modules', ModulesViewSet)              # Modules API
router.register(r'permissions', PermissionsViewSet)      # Permissions API
router.register(r'role-permissions', RolePermissionsViewSet)  # Role ↔ Permission mapping
router.register(r'roles', RolesViewSet)                  # Roles API
router.register(r'user-roles', UserRolesViewSet)         # User ↔ Role mapping
router.register(r'role-hierarchy', RoleHierarchyViewSet) # Role hierarchy API

# Optional RBAC Extensions
# router.register(r'sod-forbidden-pairs', SodForbiddenPairsViewSet)  # Segregation of Duties (Forbidden Pairs)
# router.register(r'sod-policies', SodPoliciesViewSet)               # SoD Policies

# Include router URLs
urlpatterns = [
    path('', include(router.urls)),  # Auto-generated routes for all registered viewsets
]
