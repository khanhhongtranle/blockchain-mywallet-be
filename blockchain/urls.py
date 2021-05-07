from django.urls import path
from . import views

urlpatterns = [
    path('access_my_wallet', views.access_my_wallet),
    path('create_new_wallet',views.create_new_wallet),
    path('register_new_node',views.register_new_peer),
    path('register_existing_node',views.register_with_exixting_node),
    path('chains',views.get_chain),
    path('new_transaction',views.new_transaction),
    path('mine',views.mine_unconfirmed_transactions),
    path('pending_tx',views.get_pending_tx),
    path('add_block',views.verify_and_add_block),
    path('amount',views.get_amount)
]
