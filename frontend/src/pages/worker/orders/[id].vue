<script setup>
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useOrderStore } from '@/stores/order';
import BackButton from "@/components/BackButton.vue";
import {useAuthStore} from "@/stores/auth";
import router from "@/router";

const route = useRoute();
const orderId = route.params.id;
const order = ref({});

const orderStore = useOrderStore();

onMounted(async () => {
  await orderStore.fetchOrderById(orderId);
  order.value = orderStore.order;
});

const updateOrderStatus = async (newStatus) => {
  await orderStore.updateOrder(orderId, newStatus);
  window.location.reload();
};

const statusTranslations = {
  CREATED: 'Kreirano',
  ACCEPTED: 'Prihvaćeno',
  REJECTED: 'Odbijeno',
  IN_DELIVERY: 'U dostavi',
  DELIVERED: 'Dostavljeno',
};

const translatedStatus = computed(() => statusTranslations[order.value.status] || order.value.status);

const formatDateAndTime = (date) => {
  const options = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' };
  return new Date(date).toLocaleDateString('hr-HR', options);
};

const authStore = useAuthStore();

onMounted(async () => {
  if (authStore.auth.role !== 'ADMIN' && authStore.auth.role !== 'WORKER') await router.push('/');
})
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton/>
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Detalji narudžbe</h1>
        </div>
      </v-col>
    </v-row>
    <v-row justify="center" class="pb-4">
      <v-col cols="12" sm="10" md="8" lg="6">
        <v-card class="custom-shadow pa-4" rounded="xl">
          <v-card-title class="text-h6 text-sm-h5 text-start text-black">
            Narudžba #{{ order.id }}
          </v-card-title>
          <v-card-subtitle class="text-subtitle-2 text-sm-subtitle-1 text-black">
            {{ formatDateAndTime(order.createdAt) }}
          </v-card-subtitle>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 text-grey-darken-3">
            <span class="font-weight-medium">Status:</span> {{ translatedStatus }}
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 text-grey-darken-3">
            <span class="font-weight-medium">Ukupna cijena:</span> {{ order.totalPrice }} KM
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 text-grey-darken-3">
            <span class="font-weight-medium">Adresa:</span> {{ order.address }} {{ order.addressNumber }},
            <span class="font-weight-medium">Kat:</span> {{ order.floorNumber }}
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 mx-4 text-grey-darken-3">
            <ul v-for="item in order.orderItems">
              <li :key="item.id">
                {{ item.foodName }} - {{ item.quantity }} x {{ item.foodPrice }} KM
              </li>
            </ul>
          </v-card-text>
          <v-card-actions>
            <div v-if="order.status === 'CREATED'" class="d-flex justify-space-evenly w-100 mx-4 my-2">
              <v-btn @click="() => updateOrderStatus('ACCEPTED')" color="green-lighten-1" variant="flat"
                     class="w-50 mx-2 custom-radius" prepend-icon="mdi-check-circle"
              >
                Prihvati narudžbu
              </v-btn>
              <v-btn @click="() => updateOrderStatus('REJECTED')" color="red-lighten-1" variant="flat"
                     class="w-50 mx-2 custom-radius" prepend-icon="mdi-close-circle"
              >
                Odbij narudžbu
              </v-btn>
            </div>
            <v-btn v-if="order.status === 'ACCEPTED'" @click="() => updateOrderStatus('IN_DELIVERY')"
                   color="primary" variant="flat" class="w-100 custom-radius"
            >
              Označi kao u dostavi
            </v-btn>
            <v-btn v-if="order.status === 'IN_DELIVERY'" @click="() => updateOrderStatus('DELIVERED')"
                   color="primary" variant="flat" class="w-100 custom-radius"
            >
              Označi kao dostavljeno
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
