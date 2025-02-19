<script setup>

import BackButton from "@/components/BackButton.vue";
import OrderUserCard from "@/components/OrderUserCard.vue";
import {useOrderStore} from "@/stores/order";

const orderStore = useOrderStore();

const orders = ref([]);

onMounted(async () => {
  await orderStore.fetchUserOrders();
  orders.value = orderStore.orders;
  console.log(orders.value);
});

const createdOrders = computed(() => {
  return orders.value.filter(order => order.status === 'CREATED');
});

const acceptedOrders = computed(() => {
  return orders.value.filter(order => order.status === 'ACCEPTED');
});

const inDeliveryOrders = computed(() => {
  return orders.value.filter(order => order.status === 'IN_DELIVERY');
});

const deliveredOrders = computed(() => {
  return orders.value.filter(order => order.status === 'DELIVERED');
});

const rejectedOrders = computed(() => {
  return orders.value.filter(order => order.status === 'REJECTED');
});
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton/>
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Moje narudžbe</h1>
        </div>
      </v-col>
    </v-row>
    <v-row class="py-6">
      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h1 class="text-h5 text-md-h4 mb-4 font-weight-medium">
          <v-icon icon="mdi-timer-sand"/>
          Na čekanju
        </h1>
        <v-col v-for="order in createdOrders" class="mb-2">
          <OrderUserCard :createdAt="order.createdAt" status="Kreirana" :id="order.id" :total-price="order.totalPrice"/>
        </v-col>
        <v-divider/>
      </v-col>

      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h1 class="text-h5 text-md-h4 mb-4 font-weight-medium">
          <v-icon icon="mdi-progress-clock"/>
          U pripremi
        </h1>
        <v-col v-for="order in acceptedOrders" class="mb-2">
          <OrderUserCard :createdAt="order.createdAt" status="Prihvaćena" :id="order.id" :total-price="order.totalPrice"/>
        </v-col>
        <v-divider/>
      </v-col>

      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h1 class="text-h5 text-md-h4 mb-4 font-weight-medium">
          <v-icon icon="mdi-truck-delivery"/>
          Na putu
        </h1>
        <v-col v-for="order in inDeliveryOrders" class="mb-2">
          <OrderUserCard :createdAt="order.createdAt" status="U dostavi" :id="order.id" :total-price="order.totalPrice"/>
        </v-col>
        <v-divider/>
      </v-col>

      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h1 class="text-h5 text-md-h4 mb-4 font-weight-medium">
          <v-icon icon="mdi-check-all"/>
          Dostavljene
        </h1>
        <v-col v-for="order in deliveredOrders" class="mb-2">
          <OrderUserCard :createdAt="order.createdAt" status="Dostavljena" :id="order.id" :total-price="order.totalPrice"/>
        </v-col>
        <v-divider/>
      </v-col>

      <v-col cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h1 class="text-h5 text-md-h4 mb-4 font-weight-medium">
          <v-icon icon="mdi-window-close"/>
          Odbijene
        </h1>
        <v-col v-for="order in rejectedOrders" class="mb-2">
          <OrderUserCard :createdAt="order.createdAt" status="Odbijena" :id="order.id" :total-price="order.totalPrice"/>
        </v-col>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
