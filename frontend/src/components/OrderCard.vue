<script setup>

const props = defineProps({
  id: {
    type: String,
    default: 1,
  },
  createdAt: {
    type: Date,
    default: '',
  },
  title: {
    type: String,
    default: 'Narudžba',
  },
  totalPrice: {
    type: String,
    default: '0',
  },
  status: {
    type: String,
    default: '',
  },
});

const formatDateAndTime = (date) => {
  const options = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' };
  return new Date(date).toLocaleDateString('hr-HR', options);
};
</script>

<template>
  <RouterLink :to="`/worker/orders/${props.id}`"  class="text-decoration-none">
    <v-card class="d-flex align-center mb-2 pa-2 custom-shadow" rounded="xl" variant="text">
      <div class="d-flex flex-column align-center justify-start">
        <v-card-title class="text-h6 text-sm-h5 text-start text-black">
          {{ title }} #{{ id }}
        </v-card-title>
        <v-card-subtitle class="text-subtitle-2 text-sm-subtitle-1 text-black">
          {{ formatDateAndTime(createdAt) }}
        </v-card-subtitle>
        <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 text-grey-darken-3">
          Status: {{ status }}
        </v-card-text>
      </div>
      <v-card-text class="w-100 w-sm-auto text-end text-h5 text-sm-h4 font-weight-medium text-end mr-sm-4 mt-3 text-primary">
        {{ totalPrice }} KM
      </v-card-text>
    </v-card>
  </RouterLink>
</template>

<style scoped>
.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
