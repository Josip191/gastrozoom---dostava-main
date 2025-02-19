<script setup>
const props = defineProps({
  id: {
    type: String,
    default: '',
  },
  imageSrc: {
    type: String,
    default: '',
  },
  title: {
    type: String,
    default: 'Naziv jela',
  },
  price: {
    type: String,
    default: '0',
  },
  quantity: {
    type: String,
    default: '0',
  },
});

const totalPrice = props.price * props.quantity;
</script>

<template>
  <RouterLink :to="`/food/${id}`" class="text-decoration-none">
    <v-card class="d-flex align-center my-6 custom-shadow" rounded="xl" variant="text">
      <v-img :src="imageSrc" class="bg-grey-lighten-2 ma-3 align-center custom-radius" width="80px" max-width="80px"
             height="80px">
        <template #placeholder>
          <v-icon class="text-center w-100 fill-height">mdi-image</v-icon>
        </template>
      </v-img>

      <div class="d-flex flex-column align-center justify-start">
        <v-card-title class="text-h6 text-sm-h5 text-start text-black">
          {{ title }}
        </v-card-title>
        <v-card-text class="text-subtitle-1 text-sm-h6 text-start mt-3 text-grey-darken-3">
          {{ quantity }} x {{ price }} KM
        </v-card-text>
      </div>
      <v-card-text class="w-100 w-sm-auto text-end text-h5 text-sm-h4 font-weight-medium text-end mr-sm-4 mt-3 text-primary">
        {{ totalPrice }} KM
      </v-card-text>
    </v-card>
  </RouterLink>
</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
