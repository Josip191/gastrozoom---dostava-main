<script setup>
import BackButton from "@/components/BackButton.vue";
import FoodCard from "@/components/FoodCard.vue";
import {ref} from "vue";
import {useFoodStore} from "@/stores/food";

const search = ref("");
const foods = ref([])

const foodStore = useFoodStore();

onMounted(
  async () => {
    await foodStore.fetchFoods();
    foods.value = foodStore.foods;
    console.log(foods.value);
  }
);

watch(
  () => foodStore.foods,
  (newFoods) => {
    foods.value = newFoods;
  }
);

const filteredFoods = computed(() => {
  return foods.value.filter((food) => {
    return food.name.toLowerCase().includes(search.value.toLowerCase());
  });
});

const sortByPriceAscending = () => {
  foods.value.sort((a, b) => a.price - b.price);
};

const sortByPriceDescending = () => {
  foods.value.sort((a, b) => b.price - a.price);
};

const sortByNameAscending = () => {
  foods.value.sort((a, b) => a.name.localeCompare(b.name));
};

const sortByNameDescending = () => {
  foods.value.sort((a, b) => b.name.localeCompare(a.name));
};

const sortByCategory = () => {
  foods.value.sort((a, b) => a.category.localeCompare(b.category));
};

const filters = [
  { icon: "mdi-chevron-up", title: "Cijena rastuće", action: sortByPriceAscending },
  { icon: "mdi-chevron-down", title: "Cijena opadajuće", action: sortByPriceDescending },
  { icon: "mdi-chevron-up", title: "Naziv rastuće", action: sortByNameAscending },
  { icon: "mdi-chevron-down", title: "Naziv opadajuće", action: sortByNameDescending },
  { icon: "mdi-shape", title: "Kategorija", action: sortByCategory },
];
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton/>
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Ponude</h1>
        </div>
      </v-col>
    </v-row>
    <v-row justify="center" class="pb-4">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <v-text-field
          v-model="search"
          class="custom-text-field elevation-0 bg-secondary rounded-xl pl-8 pr-4"
          append-inner-icon="mdi-magnify"
          label="Pretraži"
          variant="plain"
          density="comfortable"
          clearable
          rounded
          hide-details
        />
        <v-menu location="bottom" offset="8">
          <template v-slot:activator="{ props }">
            <v-btn icon="mdi-filter-variant" class="ml-6 custom-radius" color="primary" variant="tonal" v-bind="props"/>
          </template>
          <v-list rounded="xl" elevation="0" bg-color="primary" variant="flat">
            <v-list-item
              class="bg-primary"
              v-for="(item, index) in filters"
              :key="index"
              @click="item.action"
            >
              <v-list-item-title><v-icon class="mr-1" :icon="item.icon"/> {{ item.title }}</v-list-item-title>
            </v-list-item>
          </v-list>
        </v-menu>
      </v-col>
    </v-row>
    <v-row class="pb-16">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3"
             class="d-flex justify-center mb-2" v-if="foods.length === 0"
      >
        <h1 class="text-h4 text-sm-h3 text-primary text-center">Nema ponuda</h1>
      </v-col>
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" v-for="food in filteredFoods">
        <FoodCard :id="food.id" :image-src="food.imageUrl" :title="food.name" :price="food.price"/>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}
</style>
