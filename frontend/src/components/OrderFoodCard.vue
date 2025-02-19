<script setup>
import {defineProps} from 'vue';
import {ref} from 'vue';
import {useBasketStore} from "@/stores/basket";

const props = defineProps({
  id: {
    type: Number,
    default: null,
  },
  src: {
    type: String,
    default: '',
  },
  title: {
    type: String,
    default: 'Naziv jela',
  },
  price: {
    type: Number,
    default: 0,
  },
  removeFoodFromBasket: {
    type: Function,
    default: () => {
    },
  },
  quantity: {
    type: Number,
    default: 1,
  },
});

const quantity = ref(1);
const inputWidth = ref(42);

const basketStore = useBasketStore();

const updateWidth = () => {
  const inputLength = quantity.value.toString().length;
  inputWidth.value = Math.max((inputLength + 1) * 10 + 20, 42);
};

const onQuantityChange = () => {
  updateWidth();
  if (quantity.value < 1) {
    quantity.value = 1;
  }
  basketStore.updateFoodQuantity(props.id, quantity.value);
};

const increaseQuantity = () => {
  quantity.value += 1;
  onQuantityChange();
};

const decreaseQuantity = () => {
  if (quantity.value > 1) {
    quantity.value -= 1;
    onQuantityChange();
  }
};

onMounted(() => {
  quantity.value = basketStore.getFoodQuantity(props.id);
  console.log(props.id);
});
</script>

<template>

  <v-card :class="$vuetify.display.xs ? 'flex-column' : ''" class="d-flex align-center mb-2 custom-shadow px-4 px-sm-0"
          rounded="xl" variant="text"
  >
    <v-btn variant="plain" class="mt-3 mt-sm-0 ml-sm-2 pr-0 w-100 w-sm-auto justify-end justify-sm-center"
           @click="() => removeFoodFromBasket(props.id)"
    >
      <span v-if="$vuetify.display.xs" class="text-h5 pr-2">Ukloni</span>
      <v-icon class="text-end text-sm-center" size="2rem">mdi-window-close</v-icon>
    </v-btn>
    <v-img :src="src" class="bg-grey-lighten-2 my-4 ma-sm-3 align-center custom-radius"
           :width="$vuetify.display.xs ? '100%' : '80px'" :height="$vuetify.display.xs ? '100px' : '80px'"
    >
      <v-icon class="text-center w-100">mdi-image</v-icon>
    </v-img>
    <div class="d-flex flex-column flex-sm-row w-100">
      <div>
        <v-card-title class="text-h6 text-start">{{ title }}</v-card-title>
        <v-card-text class="text-h5 font-weight-medium text-start mr-sm-4 text-primary">{{ price }} KM</v-card-text>
      </div>
      <v-spacer/>

      <div class="d-inline-flex align-center justify-center justify-sm-end">
        <v-btn icon="mdi-minus" class="custom-radius" color="primary" variant="tonal" size="small"
               @click="decreaseQuantity"/>
        <v-text-field density="compact" variant="plain" type="number" step="1" min="1"
                      v-model="quantity" hide-spin-buttons single-line min-width="42px"
                      :style="{ maxWidth: `${inputWidth}px` }"
                      class="font-weight-medium text-center px-4 mt-5"></v-text-field>
        <v-btn icon="mdi-plus" class="mr-sm-6 custom-radius" color="primary" variant="flat" size="small"
               @click="increaseQuantity"/>
      </div>
    </div>

  </v-card>


</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
