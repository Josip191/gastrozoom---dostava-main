<script setup>
import {ref} from 'vue';
import BackButton from "@/components/BackButton.vue";
import {useAuthStore} from "@/stores/auth";
import router from "@/router";

const visible = ref(false);
const isFocused = ref(false);
const alertMessage = ref('');
const alertVisible = ref(false);
const isAuthenticated = ref(false);

const authStore = useAuthStore();

const form = ref({
  name: '',
  phoneNumber: '',
  email: '',
  password: '',
});

const handleFocus = () => {
  isFocused.value = true;
};

const handleBlur = () => {
  isFocused.value = false;
};

const submit = async () => {
  try {
    await authStore.register(form.value);
    await router.push('/');
    window.location.reload();
  } catch (error) {
    if (error.response.status >= 400) {
      alertMessage.value = error.response.data.error;
      alertVisible.value = true;
    }
  }
};

onMounted(async () => {
  isAuthenticated.value = authStore.auth.isAuthenticated;
  if (isAuthenticated.value) await router.push('/');
})
</script>

<template>
  <v-container fluid class="fill-height">
    <v-row>
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" class="pt-8">
        <BackButton />
      </v-col>
      <v-col  cols="12" sm="8" md="6" lg="4" offset-sm="2" offset-md="3" offset-lg="4">
        <h4 class="text-h4 text-center font-weight-medium pb-12">Registruj se</h4>
        <v-form @submit.prevent="submit">
          <v-text-field density="compact" placeholder="Ime i prezime" prepend-inner-icon="mdi-account" rounded
                        variant="outlined" v-model="form.name" class="mb-1" append-inner-icon="."/>

          <v-text-field density="compact" placeholder="Broj telefona" prepend-inner-icon="mdi-phone" rounded
                        variant="outlined" v-model="form.phoneNumber" class="mb-1" append-inner-icon="."/>

          <v-text-field density="compact" placeholder="Email" prepend-inner-icon="mdi-email-outline" rounded
                        variant="outlined" v-model="form.email" class="mb-1" append-inner-icon="."/>

          <v-text-field placeholder="Unesite lozinku" v-model="form.password" :type="visible ? 'text' : 'password'"
                        prepend-inner-icon="mdi-lock-outline" variant="outlined" rounded density="compact"
                        @focus="handleFocus" @blur="handleBlur" class="mb-4"
          >
            <template v-slot:append-inner>
              <v-icon @click="visible = !visible">
                {{ isFocused ? (visible ? 'mdi-eye-off' : 'mdi-eye') : undefined }}
              </v-icon>
            </template>
          </v-text-field>

          <v-alert v-model="alertVisible" density="compact" variant="tonal" type="error" class="mb-4" rounded="xl">
            {{ alertMessage }}
          </v-alert>

          <v-btn type="submit" block variant="flat" color="primary" size="large" class="mb-8 mt-2" rounded>
            Registruj se
          </v-btn>
        </v-form>
        <div class="text-center">
          <span>Već imate račun?</span>
          <RouterLink class="text-primary text-decoration-none pl-1" to="/login">
            Prijavi se!
          </RouterLink>
        </div>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
